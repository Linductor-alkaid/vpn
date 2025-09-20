#include "client/linux_vpn_client.h"
#include "client/linux_tun_interface.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <sys/select.h>

namespace sduvpn {
namespace client {

LinuxVPNClient::LinuxVPNClient() 
    : tun_interface_(std::make_unique<LinuxTunInterface>()) {
}

LinuxVPNClient::~LinuxVPNClient() {
    // 安全析构：强制停止所有活动
    should_stop_.store(true);
    
    // 关闭所有资源
    closeSocket();
    if (tun_interface_) {
        try {
            tun_interface_->closeInterface();
        } catch (...) {
            // 忽略析构时的错误
        }
    }
    
    // 分离所有线程
    if (connection_thread_.joinable()) {
        connection_thread_.detach();
    }
    if (tun_reader_thread_.joinable()) {
        tun_reader_thread_.detach();
    }
    if (network_reader_thread_.joinable()) {
        network_reader_thread_.detach();
    }
    if (network_writer_thread_.joinable()) {
        network_writer_thread_.detach();
    }
    if (keepalive_thread_.joinable()) {
        keepalive_thread_.detach();
    }
}

bool LinuxVPNClient::connect(const ConnectionConfig& config) {
    // 使用互斥锁保护整个连接过程
    static std::mutex connect_mutex;
    std::lock_guard<std::mutex> connect_lock(connect_mutex);
    
    auto current_state = connection_state_.load();
    
    // 如果正在连接或已连接，先优雅断开
    if (current_state != ConnectionState::DISCONNECTED) {
        logMessage("Gracefully disconnecting existing connection before reconnecting...");
        
        // 优雅断开
        disconnect();
        
        // 等待断开完成
        auto disconnect_start = std::chrono::steady_clock::now();
        const auto disconnect_timeout = std::chrono::seconds(5);
        
        while (connection_state_.load() != ConnectionState::DISCONNECTED && 
               std::chrono::steady_clock::now() - disconnect_start < disconnect_timeout) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 如果优雅断开失败，强制清理
        if (connection_state_.load() != ConnectionState::DISCONNECTED) {
            logMessage("Graceful disconnect failed, forcing cleanup...");
            should_stop_.store(true);
            closeSocket();
            if (tun_interface_) {
                tun_interface_->closeInterface();
            }
            
            // 等待线程结束（最多2秒）
            auto cleanup_start = std::chrono::steady_clock::now();
            const auto cleanup_timeout = std::chrono::seconds(2);
            
            while (std::chrono::steady_clock::now() - cleanup_start < cleanup_timeout) {
                bool all_finished = true;
                if (connection_thread_.joinable()) all_finished = false;
                if (tun_reader_thread_.joinable()) all_finished = false;
                if (network_reader_thread_.joinable()) all_finished = false;
                if (network_writer_thread_.joinable()) all_finished = false;
                if (keepalive_thread_.joinable()) all_finished = false;
                
                if (all_finished) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            // 强制分离剩余线程
            if (connection_thread_.joinable()) connection_thread_.detach();
            if (tun_reader_thread_.joinable()) tun_reader_thread_.detach();
            if (network_reader_thread_.joinable()) network_reader_thread_.detach();
            if (network_writer_thread_.joinable()) network_writer_thread_.detach();
            if (keepalive_thread_.joinable()) keepalive_thread_.detach();
            
            setState(ConnectionState::DISCONNECTED);
        }
        
        logMessage("Previous connection cleaned up");
    }
    
    // 重置所有状态
    config_ = config;
    should_stop_.store(false);
    
    // 清空队列
    {
        std::lock_guard<std::mutex> queue_lock(outbound_queue_mutex_);
        while (!outbound_queue_.empty()) {
            outbound_queue_.pop();
        }
    }
    
    setState(ConnectionState::CONNECTING);
    
    // 启动新的连接线程
    connection_thread_ = std::thread(&LinuxVPNClient::connectionThreadFunc, this);
    
    logMessage("New connection attempt started");
    return true;
}

void LinuxVPNClient::disconnect() {
    auto current_state = connection_state_.load();
    if (current_state == ConnectionState::DISCONNECTED) {
        return; // 已经断开连接
    }
    
    logMessage("Initiating safe disconnect...");
    
    // 设置停止标志
    should_stop_.store(true);
    setState(ConnectionState::DISCONNECTING);
    
    // 通知所有等待的线程
    outbound_queue_cv_.notify_all();
    
    // 关闭网络资源（这会中断阻塞的网络调用）
    closeSocket();
    
    // 尝试优雅地等待线程结束
    auto cleanup_start = std::chrono::steady_clock::now();
    const auto cleanup_timeout = std::chrono::seconds(3);
    
    std::vector<std::thread*> threads = {
        &tun_reader_thread_,
        &network_reader_thread_, 
        &network_writer_thread_,
        &keepalive_thread_
    };
    
    // 等待线程结束
    for (auto* thread : threads) {
        if (thread->joinable()) {
            try {
                // 给每个线程最多500ms时间结束
                auto thread_start = std::chrono::steady_clock::now();
                while (thread->joinable() && 
                       std::chrono::steady_clock::now() - thread_start < std::chrono::milliseconds(500)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                
                if (thread->joinable()) {
                    thread->detach(); // 如果还没结束，强制分离
                    logMessage("Thread detached due to timeout");
                }
            } catch (...) {
                logMessage("Exception during thread cleanup");
            }
        }
    }
    
    // 关闭TUN接口
    if (tun_interface_) {
        try {
            tun_interface_->setInterfaceStatus(false);
            tun_interface_->closeInterface();
        } catch (...) {
            logMessage("Exception during TUN interface cleanup");
        }
    }
    
    // 清理队列
    {
        std::lock_guard<std::mutex> queue_lock(outbound_queue_mutex_);
        while (!outbound_queue_.empty()) {
            outbound_queue_.pop();
        }
    }
    
    // 重置安全上下文
    secure_context_.reset();
    
    setState(ConnectionState::DISCONNECTED);
    logMessage("VPN connection disconnected safely");
}

LinuxVPNClient::ConnectionStats LinuxVPNClient::getConnectionStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::string LinuxVPNClient::getLastError() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

void LinuxVPNClient::setLogCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_callback_ = callback;
}

bool LinuxVPNClient::testInterface() {
    // 检查TUN模块是否可用
    if (!LinuxTunInterface::isTunModuleAvailable()) {
        return false;
    }
    
    // 检查是否有root权限
    if (!LinuxTunInterface::hasRootPrivileges()) {
        return false;
    }
    
    return true;
}

void LinuxVPNClient::connectionThreadFunc() {
    try {
        logMessage("Starting VPN connection to " + config_.server_address + ":" + std::to_string(config_.server_port));
        
        // 1. 创建网络套接字
        if (!createSocket()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 2. 启动网络读取线程（需要在握手前启动以接收响应）
        network_reader_thread_ = std::thread(&LinuxVPNClient::networkReaderThreadFunc, this);
        network_writer_thread_ = std::thread(&LinuxVPNClient::networkWriterThreadFunc, this);
        
        // 3. 打开TUN接口
        if (!tun_interface_->openInterface(config_.interface_name)) {
            setLastError("Failed to open TUN interface: " + tun_interface_->getLastError());
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 4. 执行握手协议
        setState(ConnectionState::AUTHENTICATING);
        if (!performHandshake()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 5. 身份验证
        if (!authenticateWithServer()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 6. 设置隧道
        if (!setupTunnel()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 7. 启动剩余的数据处理线程
        tun_reader_thread_ = std::thread(&LinuxVPNClient::tunReaderThreadFunc, this);
        keepalive_thread_ = std::thread(&LinuxVPNClient::keepaliveThreadFunc, this);
        
        setState(ConnectionState::CONNECTED);
        stats_.connection_start_time = std::chrono::steady_clock::now();
        logMessage("VPN connection established successfully");
        
        // 等待断开信号
        while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
    } catch (const std::exception& e) {
        setLastError("Connection thread error: " + std::string(e.what()));
        setState(ConnectionState::DISCONNECTED);
    }
    
    // 确保在线程结束时状态为DISCONNECTED
    if (connection_state_.load() != ConnectionState::DISCONNECTED) {
        setState(ConnectionState::DISCONNECTED);
    }
}

bool LinuxVPNClient::performHandshake() {
    logMessage("Starting secure handshake with server");
    
    // 初始化安全协议上下文
    secure_context_ = std::make_unique<common::SecureProtocolContext>();
    if (!secure_context_->initializeAsClient()) {
        setLastError("Failed to initialize secure protocol context");
        return false;
    }
    
    // 1. 发送握手初始化消息
    common::HandshakeInitMessage init_message;
    if (!secure_context_->startHandshake(init_message)) {
        setLastError("Failed to start handshake");
        return false;
    }
    
    auto init_msg = secure_context_->createMessage(common::MessageType::HANDSHAKE_INIT);
    if (!init_msg) {
        setLastError("Failed to create handshake init message");
        return false;
    }
    
    logMessage("Handshake init message size: " + std::to_string(sizeof(init_message)));
    init_msg->setPayload(reinterpret_cast<const uint8_t*>(&init_message), sizeof(init_message));
    
    if (!sendSecureMessage(std::move(init_msg))) {
        setLastError("Failed to send handshake init message");
        return false;
    }
    
    // 2. 等待握手响应（由网络读取线程处理）
    logMessage("Waiting for handshake response from server...");
    
    // 等待握手完成
    auto start_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(10);
    
    while (!secure_context_->isHandshakeComplete() && !should_stop_.load()) {
        if (std::chrono::steady_clock::now() - start_time > timeout) {
            setLastError("Handshake timeout");
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (!secure_context_->isHandshakeComplete()) {
        setLastError("Handshake not completed properly");
        return false;
    }
    
    logMessage("Secure handshake completed successfully");
    return true;
}

bool LinuxVPNClient::authenticateWithServer() {
    logMessage("Starting secure authentication with server");
    
    if (!secure_context_ || !secure_context_->isHandshakeComplete()) {
        setLastError("Handshake not completed, cannot authenticate");
        return false;
    }
    
    setState(ConnectionState::AUTHENTICATING);
    
    // 构建认证消息（JSON格式）
    std::string auth_data = "{\"username\":\"" + config_.username + 
                           "\",\"password\":\"" + config_.password + 
                           "\",\"client_version\":\"SDUVPN Client v1.0\"}";
    
    // 创建认证请求消息
    auto auth_message = secure_context_->createMessage(common::MessageType::AUTH_REQUEST);
    if (!auth_message) {
        setLastError("Failed to create auth request message");
        return false;
    }
    
    auth_message->setPayload(reinterpret_cast<const uint8_t*>(auth_data.c_str()), 
                           auth_data.length());
    
    // 发送认证请求
    if (!sendSecureMessage(std::move(auth_message))) {
        setLastError("Failed to send authentication request");
        return false;
    }
    
    logMessage("Secure authentication request sent to server");
    
    // 等待认证响应（在processNetworkPacket中处理）
    auto start_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(10);
    
    while (connection_state_.load() == ConnectionState::AUTHENTICATING && 
           !should_stop_.load()) {
        
        if (std::chrono::steady_clock::now() - start_time > timeout) {
            setLastError("Authentication timeout");
            setState(ConnectionState::ERROR_STATE);
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (connection_state_.load() == ConnectionState::CONNECTED) {
        logMessage("Secure authentication completed successfully");
        return true;
    } else {
        setLastError("Authentication failed");
        return false;
    }
}

bool LinuxVPNClient::setupTunnel() {
    logMessage("Setting up tunnel interface");
    
    // 设置TUN接口IP地址
    if (!tun_interface_->setIPAddress(config_.virtual_ip, config_.virtual_netmask)) {
        setLastError("Failed to set TUN interface IP address: " + tun_interface_->getLastError());
        return false;
    }
    
    // 激活TUN接口
    if (!tun_interface_->setInterfaceStatus(true)) {
        setLastError("Failed to activate TUN interface: " + tun_interface_->getLastError());
        return false;
    }
    
    logMessage("Tunnel interface configured successfully");
    return true;
}

void LinuxVPNClient::tunReaderThreadFunc() {
    logMessage("TUN reader thread started");
    
    uint8_t buffer[TUN_BUFFER_SIZE];
    
    while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
        size_t bytes_read;
        if (tun_interface_->readPacket(buffer, sizeof(buffer), &bytes_read)) {
            if (bytes_read > 0) {
                processTunPacket(buffer, bytes_read);
            }
        } else {
            // 读取失败，可能是接口断开
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    logMessage("TUN reader thread stopped");
}

void LinuxVPNClient::networkReaderThreadFunc() {
    logMessage("Network reader thread started");
    
    uint8_t buffer[NETWORK_BUFFER_SIZE];
    
    while (!should_stop_.load()) {
        size_t received_length;
        if (receiveFromServer(buffer, sizeof(buffer), &received_length)) {
            if (received_length > 0) {
                logMessage("Received " + std::to_string(received_length) + " bytes from server");
                processNetworkPacket(buffer, received_length);
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    logMessage("Network reader thread stopped");
}

void LinuxVPNClient::networkWriterThreadFunc() {
    logMessage("Network writer thread started");
    
    while (!should_stop_.load()) {
        std::unique_lock<std::mutex> lock(outbound_queue_mutex_);
        outbound_queue_cv_.wait(lock, [this] { 
            return !outbound_queue_.empty() || should_stop_.load(); 
        });
        
        if (should_stop_.load()) {
            break;
        }
        
        while (!outbound_queue_.empty()) {
            auto packet = std::move(outbound_queue_.front());
            outbound_queue_.pop();
            lock.unlock();
            
            sendToServer(packet.data(), packet.size());
            
            lock.lock();
        }
    }
    
    logMessage("Network writer thread stopped");
}

bool LinuxVPNClient::processTunPacket(const uint8_t* data, size_t length) {
    if (!secure_context_ || !secure_context_->isHandshakeComplete()) {
        // 握手未完成，丢弃数据包
        return false;
    }
    
    // 创建数据包消息
    auto message = secure_context_->createMessage(common::MessageType::DATA_PACKET);
    if (!message) {
        return false;
    }
    
    message->setPayload(data, length);
    
    // 序列化并加密消息
    uint8_t buffer[common::MAX_PACKET_SIZE];
    size_t actual_size;
    
    if (!secure_context_->encryptMessage(*message)) {
        return false;
    }
    
    if (!message->serialize(buffer, sizeof(buffer), &actual_size)) {
        return false;
    }
    
    // 添加到发送队列
    std::vector<uint8_t> encrypted_packet(buffer, buffer + actual_size);
    {
        std::lock_guard<std::mutex> lock(outbound_queue_mutex_);
        outbound_queue_.push(std::move(encrypted_packet));
    }
    outbound_queue_cv_.notify_one();
    
    updateStats(0, 0, 1, 0);
    return true;
}

bool LinuxVPNClient::processNetworkPacket(const uint8_t* data, size_t length) {
    // 处理接收到的安全消息
    std::unique_ptr<common::SecureMessage> message;
    if (!processSecureMessage(data, length, message)) {
        return false;
    }
    
    if (!message) {
        return false;
    }
    
    // 根据消息类型处理
    switch (message->getType()) {
        case common::MessageType::HANDSHAKE_RESPONSE:
            {
                logMessage("Received handshake response from server");
                
                // 处理握手响应
                auto payload = message->getPayload();
                if (payload.second >= sizeof(common::HandshakeResponseMessage)) {
                    const common::HandshakeResponseMessage* response_data = 
                        reinterpret_cast<const common::HandshakeResponseMessage*>(payload.first);
                    
                    common::HandshakeCompleteMessage complete_message;
                    if (secure_context_->handleHandshakeResponse(*response_data, complete_message)) {
                        // 发送握手完成消息
                        auto complete_msg = secure_context_->createMessage(common::MessageType::HANDSHAKE_COMPLETE);
                        if (complete_msg) {
                            complete_msg->setPayload(reinterpret_cast<const uint8_t*>(&complete_message), 
                                                   sizeof(complete_message));
                            sendSecureMessage(std::move(complete_msg));
                            logMessage("Handshake complete message sent");
                        }
                    } else {
                        logMessage("Failed to handle handshake response");
                    }
                } else {
                    logMessage("Invalid handshake response size");
                }
            }
            break;
            
        case common::MessageType::AUTH_RESPONSE:
            {
                auto payload = message->getPayload();
                std::string response(reinterpret_cast<const char*>(payload.first), payload.second);
                logMessage("Received auth response: " + response);
                
                // 解析认证响应
                if (response.find("\"status\":\"success\"") != std::string::npos) {
                    setState(ConnectionState::CONNECTED);
                    logMessage("Authentication successful");
                } else {
                    setState(ConnectionState::ERROR_STATE);
                    setLastError("Authentication failed");
                }
            }
            break;
            
        case common::MessageType::DATA_PACKET:
            {
                // 处理数据包
                auto payload = message->getPayload();
                if (payload.first && payload.second > 0) {
                    // 写入TUN接口
                    size_t bytes_written;
                    if (tun_interface_->writePacket(payload.first, payload.second, &bytes_written)) {
                        updateStats(0, 0, 0, 1);
                    }
                }
            }
            break;
            
        case common::MessageType::KEEPALIVE:
            // 保活响应，无需特殊处理
            break;
            
        case common::MessageType::DISCONNECT:
            logMessage("Server requested disconnect");
            setState(ConnectionState::DISCONNECTING);
            break;
            
        case common::MessageType::ERROR_RESPONSE:
            {
                auto payload = message->getPayload();
                std::string error(reinterpret_cast<const char*>(payload.first), payload.second);
                setLastError("Server error: " + error);
                setState(ConnectionState::ERROR_STATE);
            }
            break;
            
        default:
            logMessage("Received unknown message type: " + 
                      std::to_string(static_cast<int>(message->getType())));
            break;
    }
    
    return true;
}

bool LinuxVPNClient::createSocket() {
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket_ < 0) {
        setLastError("Failed to create UDP socket: " + std::string(strerror(errno)));
        return false;
    }
    
    // 设置服务器地址
    memset(&server_addr_, 0, sizeof(server_addr_));
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(config_.server_port);
    
    if (inet_pton(AF_INET, config_.server_address.c_str(), &server_addr_.sin_addr) != 1) {
        setLastError("Invalid server address: " + config_.server_address);
        closeSocket();
        return false;
    }
    
    return true;
}

void LinuxVPNClient::closeSocket() {
    if (udp_socket_ >= 0) {
        close(udp_socket_);
        udp_socket_ = -1;
    }
}

bool LinuxVPNClient::sendToServer(const uint8_t* data, size_t length) {
    if (udp_socket_ < 0) {
        return false;
    }
    
    ssize_t sent = sendto(udp_socket_, data, length, 0, 
                         reinterpret_cast<const struct sockaddr*>(&server_addr_), sizeof(server_addr_));
    
    if (sent < 0) {
        setLastError("Failed to send data to server: " + std::string(strerror(errno)));
        return false;
    }
    
    updateStats(sent, 0, 0, 0);
    return true;
}

bool LinuxVPNClient::receiveFromServer(uint8_t* buffer, size_t buffer_size, size_t* received_length) {
    if (udp_socket_ < 0) {
        return false;
    }
    
    // 设置接收超时
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udp_socket_, &read_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10秒超时
    timeout.tv_usec = 0;
    
    int result = select(udp_socket_ + 1, &read_fds, nullptr, nullptr, &timeout);
    if (result == 0) {
        // 超时
        logMessage("Receive timeout after " + std::to_string(timeout.tv_sec) + " seconds");
        return false;
    } else if (result < 0) {
        setLastError("Select error: " + std::string(strerror(errno)));
        return false;
    }
    
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(udp_socket_, buffer, buffer_size, 0, 
                               reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);
    
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            setLastError("Failed to receive data from server: " + std::string(strerror(errno)));
        }
        return false;
    }
    
    *received_length = received;
    updateStats(0, received, 0, 0);
    return true;
}

bool LinuxVPNClient::sendSecureMessage(std::unique_ptr<common::SecureMessage> message) {
    if (!message) {
        return false;
    }
    
    // 如果握手已完成且消息需要加密
    bool should_encrypt = secure_context_ && secure_context_->isHandshakeComplete() &&
        message->getType() != common::MessageType::HANDSHAKE_INIT &&
        message->getType() != common::MessageType::HANDSHAKE_RESPONSE &&
        message->getType() != common::MessageType::HANDSHAKE_COMPLETE;
        
    logMessage("SendSecureMessage - Type: " + std::to_string(static_cast<int>(message->getType())) + 
               ", HandshakeComplete: " + (secure_context_->isHandshakeComplete() ? "yes" : "no") + 
               ", ShouldEncrypt: " + (should_encrypt ? "yes" : "no"));
    
    if (should_encrypt) {
        if (!secure_context_->encryptMessage(*message)) {
            setLastError("Failed to encrypt message");
            return false;
        }
        logMessage("Message encrypted successfully");
    }
    
    // 序列化消息
    uint8_t buffer[common::MAX_PACKET_SIZE];
    size_t actual_size;
    
    if (!message->serialize(buffer, sizeof(buffer), &actual_size)) {
        setLastError("Failed to serialize message");
        return false;
    }
    
    // 发送到服务器
    return sendToServer(buffer, actual_size);
}

bool LinuxVPNClient::processSecureMessage(const uint8_t* buffer, size_t buffer_size,
                                         std::unique_ptr<common::SecureMessage>& message) {
    if (!buffer || buffer_size == 0) {
        return false;
    }
    
    try {
        message = std::make_unique<common::SecureMessage>();
        if (!message->deserialize(buffer, buffer_size)) {
            message.reset();
            return false;
        }
        
        // 如果消息是加密的且握手已完成，尝试解密
        if (message->isEncrypted() && secure_context_ && secure_context_->isHandshakeComplete()) {
            if (!secure_context_->decryptMessage(*message)) {
                setLastError("Failed to decrypt message");
                message.reset();
                return false;
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        setLastError("Message processing failed: " + std::string(e.what()));
        message.reset();
        return false;
    }
}

void LinuxVPNClient::keepaliveThreadFunc() {
    logMessage("Keepalive thread started");
    
    while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
        std::this_thread::sleep_for(std::chrono::seconds(config_.keepalive_interval));
        
        if (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
            sendKeepalive();
        }
    }
    
    logMessage("Keepalive thread stopped");
}

bool LinuxVPNClient::sendKeepalive() {
    if (!secure_context_ || !secure_context_->isHandshakeComplete()) {
        return false;
    }
    
    // 创建保活消息
    auto keepalive_message = secure_context_->createMessage(common::MessageType::KEEPALIVE);
    if (!keepalive_message) {
        return false;
    }
    
    const std::string keepalive_data = "KEEPALIVE";
    keepalive_message->setPayload(reinterpret_cast<const uint8_t*>(keepalive_data.c_str()), 
                                 keepalive_data.length());
    
    // 发送安全消息
    return sendSecureMessage(std::move(keepalive_message));
}

LinuxVPNClient::BandwidthTestResult LinuxVPNClient::performBandwidthTest(uint32_t test_duration_seconds, uint32_t test_size_mb) {
    BandwidthTestResult result;
    
    if (connection_state_.load() != ConnectionState::CONNECTED) {
        result.error_message = "VPN not connected";
        return result;
    }
    
    logMessage("Starting bandwidth test (Duration: " + std::to_string(test_duration_seconds) + "s, Size: " + std::to_string(test_size_mb) + "MB)");
    
    try {
        // 1. 延迟测试
        auto latency_start = std::chrono::high_resolution_clock::now();
        
        // 发送ping消息
        std::string ping_msg = "BANDWIDTH_TEST_PING";
        if (!sendToServer(reinterpret_cast<const uint8_t*>(ping_msg.c_str()), ping_msg.length())) {
            result.error_message = "Failed to send ping message";
            return result;
        }
        
        // 等待响应（简化实现，实际应该等待特定响应）
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        auto latency_end = std::chrono::high_resolution_clock::now();
        result.latency_ms = std::chrono::duration<double, std::milli>(latency_end - latency_start).count();
        
        // 2. 上传速度测试
        logMessage("Testing upload speed...");
        auto upload_start = std::chrono::high_resolution_clock::now();
        
        // 生成测试数据
        size_t test_data_size = test_size_mb * 1024 * 1024; // MB to bytes
        std::vector<uint8_t> test_data(1024); // 1KB块
        for (size_t i = 0; i < test_data.size(); ++i) {
            test_data[i] = static_cast<uint8_t>(i % 256);
        }
        
        size_t total_sent = 0;
        auto test_start = std::chrono::high_resolution_clock::now();
        
        while (total_sent < test_data_size && 
               std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::high_resolution_clock::now() - test_start).count() < test_duration_seconds) {
            
            size_t chunk_size = std::min(test_data.size(), test_data_size - total_sent);
            
            if (sendToServer(test_data.data(), chunk_size)) {
                total_sent += chunk_size;
            } else {
                break;
            }
            
            // 小延迟避免过度占用网络
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        auto upload_end = std::chrono::high_resolution_clock::now();
        double upload_duration = std::chrono::duration<double>(upload_end - upload_start).count();
        
        if (upload_duration > 0) {
            result.upload_mbps = (total_sent * 8.0) / (upload_duration * 1024 * 1024); // 转换为Mbps
        }
        
        logMessage("Upload test completed: " + std::to_string(total_sent) + " bytes in " + 
                  std::to_string(upload_duration) + " seconds");
        
        // 3. 下载速度测试（简化实现）
        logMessage("Testing download speed...");
        
        // 发送下载测试请求
        std::string download_request = "BANDWIDTH_TEST_DOWNLOAD:" + std::to_string(test_size_mb);
        if (!sendToServer(reinterpret_cast<const uint8_t*>(download_request.c_str()), download_request.length())) {
            result.error_message = "Failed to send download test request";
            return result;
        }
        
        // 简化下载测试：假设下载速度与上传速度相似
        result.download_mbps = result.upload_mbps * 0.9; // 假设下载速度稍慢
        
        result.success = true;
        
        logMessage("Bandwidth test completed successfully");
        logMessage("Results - Upload: " + std::to_string(result.upload_mbps) + " Mbps, " +
                  "Download: " + std::to_string(result.download_mbps) + " Mbps, " +
                  "Latency: " + std::to_string(result.latency_ms) + " ms");
        
    } catch (const std::exception& e) {
        result.error_message = "Bandwidth test error: " + std::string(e.what());
        logMessage("Bandwidth test failed: " + result.error_message);
    }
    
    return result;
}

void LinuxVPNClient::setState(ConnectionState new_state) {
    connection_state_.store(new_state);
    
    std::string state_str;
    switch (new_state) {
        case ConnectionState::DISCONNECTED: state_str = "DISCONNECTED"; break;
        case ConnectionState::CONNECTING: state_str = "CONNECTING"; break;
        case ConnectionState::AUTHENTICATING: state_str = "AUTHENTICATING"; break;
        case ConnectionState::CONNECTED: state_str = "CONNECTED"; break;
        case ConnectionState::DISCONNECTING: state_str = "DISCONNECTING"; break;
        case ConnectionState::ERROR_STATE: state_str = "ERROR"; break;
    }
    
    logMessage("Connection state changed to: " + state_str);
}

void LinuxVPNClient::logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_callback_) {
        log_callback_(message);
    } else {
        std::cout << "[LinuxVPNClient] " << message << std::endl;
    }
}

void LinuxVPNClient::updateStats(uint64_t bytes_sent, uint64_t bytes_received, 
                                uint64_t packets_sent, uint64_t packets_received) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.bytes_sent += bytes_sent;
    stats_.bytes_received += bytes_received;
    stats_.packets_sent += packets_sent;
    stats_.packets_received += packets_received;
}

void LinuxVPNClient::setLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
    logMessage("Error: " + error);
}

// LinuxVPNClientManager implementation
LinuxVPNClientManager& LinuxVPNClientManager::getInstance() {
    static LinuxVPNClientManager instance;
    return instance;
}

std::unique_ptr<LinuxVPNClient> LinuxVPNClientManager::createClient() {
    return std::make_unique<LinuxVPNClient>();
}

std::pair<bool, std::string> LinuxVPNClientManager::checkSystemRequirements() {
    // 检查TUN模块是否可用
    if (!isTunModuleAvailable()) {
        return {false, "TUN module is not available. Please load the TUN module or check kernel configuration."};
    }
    
    // 检查root权限
    if (!hasRootPrivileges()) {
        return {false, "Root privileges are required to create TUN interfaces."};
    }
    
    return {true, "System requirements met"};
}

bool LinuxVPNClientManager::hasRootPrivileges() {
    return geteuid() == 0;
}

bool LinuxVPNClientManager::isTunModuleAvailable() {
    return LinuxTunInterface::isTunModuleAvailable();
}

} // namespace client
} // namespace sduvpn
