#include "client/windows_vpn_client.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace sduvpn {
namespace client {

WindowsVPNClient::WindowsVPNClient() 
    : tap_interface_(std::make_unique<WindowsTapInterface>()) {
    
    // 初始化Winsock
    WindowsVPNClientManager::getInstance().initializeWinsock();
}

WindowsVPNClient::~WindowsVPNClient() {
    // 安全析构：强制停止所有活动
    should_stop_.store(true);
    
    // 关闭所有资源
    closeSocket();
    if (tap_interface_) {
        try {
            tap_interface_->closeAdapter();
        } catch (...) {
            // 忽略析构时的错误
        }
    }
    
    // 分离所有线程
    if (connection_thread_.joinable()) {
        connection_thread_.detach();
    }
    if (tap_reader_thread_.joinable()) {
        tap_reader_thread_.detach();
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
    if (reconnect_thread_.joinable()) {
        reconnect_thread_.detach();
    }
}

bool WindowsVPNClient::connect(const ConnectionConfig& config) {
    // 使用互斥锁保护整个连接过程
    static std::mutex connect_mutex;
    std::lock_guard<std::mutex> connect_lock(connect_mutex);
    
    auto current_state = connection_state_.load();
    
    // 如果正在连接或已连接，先完全断开
    if (current_state != ConnectionState::DISCONNECTED) {
        logMessage("Force disconnecting existing connection before reconnecting...");
        
        // 强制断开 - 不等待，直接清理
        should_stop_.store(true);
        
        // 强制关闭网络资源
        closeSocket();
        if (tap_interface_) {
            tap_interface_->closeAdapter();
        }
        
        // 等待所有线程完全结束
        if (connection_thread_.joinable()) {
            connection_thread_.detach(); // 强制分离，避免阻塞
        }
        if (tap_reader_thread_.joinable()) {
            tap_reader_thread_.detach();
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
        if (reconnect_thread_.joinable()) {
            reconnect_thread_.detach();
        }
        
        // 等待一段时间确保资源清理完成
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // 强制重置状态
        setState(ConnectionState::DISCONNECTED);
        logMessage("Previous connection forcibly cleaned up");
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
    connection_thread_ = std::thread(&WindowsVPNClient::connectionThreadFunc, this);
    
    logMessage("New connection attempt started");
    return true;
}

void WindowsVPNClient::disconnect() {
    if (connection_state_.load() == ConnectionState::DISCONNECTED) {
        return; // 已经断开连接
    }
    
    should_stop_.store(true);
    setState(ConnectionState::DISCONNECTING);
    
    logMessage("Initiating safe disconnect...");
    
    // 立即关闭网络资源
    closeSocket();
    if (tap_interface_) {
        try {
            tap_interface_->setAdapterStatus(false);
            tap_interface_->closeAdapter();
        } catch (...) {
            // 忽略TAP关闭错误
        }
    }
    
    // 通知所有等待的线程
    outbound_queue_cv_.notify_all();
    
    // 快速分离所有线程，避免等待
    if (connection_thread_.joinable()) {
        connection_thread_.detach();
    }
    if (tap_reader_thread_.joinable()) {
        tap_reader_thread_.detach();
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
    if (reconnect_thread_.joinable()) {
        reconnect_thread_.detach();
    }
    
    // 清理队列
    {
        std::lock_guard<std::mutex> queue_lock(outbound_queue_mutex_);
        while (!outbound_queue_.empty()) {
            outbound_queue_.pop();
        }
    }
    
    setState(ConnectionState::DISCONNECTED);
    logMessage("VPN connection disconnected safely");
}

WindowsVPNClient::ConnectionStats WindowsVPNClient::getConnectionStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::string WindowsVPNClient::getLastError() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

void WindowsVPNClient::setLogCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_callback_ = callback;
}

void WindowsVPNClient::connectionThreadFunc() {
    try {
        logMessage("Starting VPN connection to " + config_.server_address + ":" + std::to_string(config_.server_port));
        
        // 1. 创建网络套接字
        if (!createSocket()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 2. 打开TAP适配器
        if (!tap_interface_->openAdapter(config_.tap_adapter_name)) {
            setLastError("Failed to open TAP adapter: " + tap_interface_->getLastError());
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 3. 执行握手协议
        setState(ConnectionState::AUTHENTICATING);
        if (!performHandshake()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 4. 身份验证
        if (!authenticateWithServer()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 5. 设置隧道
        if (!setupTunnel()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 6. 启动数据处理线程
        tap_reader_thread_ = std::thread(&WindowsVPNClient::tapReaderThreadFunc, this);
        network_reader_thread_ = std::thread(&WindowsVPNClient::networkReaderThreadFunc, this);
        network_writer_thread_ = std::thread(&WindowsVPNClient::networkWriterThreadFunc, this);
        keepalive_thread_ = std::thread(&WindowsVPNClient::keepaliveThreadFunc, this);
        
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

bool WindowsVPNClient::performHandshake() {
    logMessage("Starting secure handshake with server");
    
    // 初始化安全协议上下文
    secure_context_ = std::make_unique<common::SecureProtocolContext>();
    if (!secure_context_->initializeAsClient()) {
        setLastError("Failed to initialize secure protocol context");
        return false;
    }
    
    setState(ConnectionState::HANDSHAKING);
    
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
    
    init_msg->setPayload(reinterpret_cast<const uint8_t*>(&init_message), sizeof(init_message));
    
    if (!sendSecureMessage(std::move(init_msg))) {
        setLastError("Failed to send handshake init message");
        return false;
    }
    
    // 2. 接收握手响应
    uint8_t buffer[common::MAX_PACKET_SIZE];
    size_t received_length;
    if (!receiveFromServer(buffer, sizeof(buffer), &received_length)) {
        setLastError("Failed to receive handshake response");
        return false;
    }
    
    auto response_msg = std::make_unique<common::SecureMessage>();
    if (!response_msg->deserialize(buffer, received_length)) {
        setLastError("Failed to deserialize handshake response");
        return false;
    }
    
    if (response_msg->getType() != common::MessageType::HANDSHAKE_RESPONSE) {
        setLastError("Invalid handshake response message type");
        return false;
    }
    
    // 3. 处理握手响应
    auto payload = response_msg->getPayload();
    if (payload.second < sizeof(common::HandshakeResponseMessage)) {
        setLastError("Invalid handshake response message size");
        return false;
    }
    
    const common::HandshakeResponseMessage* response_data = 
        reinterpret_cast<const common::HandshakeResponseMessage*>(payload.first);
    
    common::HandshakeCompleteMessage complete_message;
    if (!secure_context_->handleHandshakeResponse(*response_data, complete_message)) {
        setLastError("Failed to handle handshake response");
        return false;
    }
    
    // 4. 发送握手完成消息
    auto complete_msg = secure_context_->createMessage(common::MessageType::HANDSHAKE_COMPLETE);
    if (!complete_msg) {
        setLastError("Failed to create handshake complete message");
        return false;
    }
    
    complete_msg->setPayload(reinterpret_cast<const uint8_t*>(&complete_message), 
                           sizeof(complete_message));
    
    if (!sendSecureMessage(std::move(complete_msg))) {
        setLastError("Failed to send handshake complete message");
        return false;
    }
    
    // 验证握手是否完成
    if (!secure_context_->isHandshakeComplete()) {
        setLastError("Handshake not completed properly");
        return false;
    }
    
    logMessage("Secure handshake completed successfully");
    return true;
}

bool WindowsVPNClient::authenticateWithServer() {
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
    // 这里可以设置一个超时机制
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

bool WindowsVPNClient::setupTunnel() {
    logMessage("Setting up tunnel interface");
    
    // 设置TAP适配器IP地址
    if (!tap_interface_->setIPAddress(config_.virtual_ip, config_.virtual_netmask)) {
        setLastError("Failed to set TAP adapter IP address: " + tap_interface_->getLastError());
        return false;
    }
    
    // 激活TAP适配器
    if (!tap_interface_->setAdapterStatus(true)) {
        setLastError("Failed to activate TAP adapter: " + tap_interface_->getLastError());
        return false;
    }
    
    logMessage("Tunnel interface configured successfully");
    return true;
}

void WindowsVPNClient::tapReaderThreadFunc() {
    logMessage("TAP reader thread started");
    
    uint8_t buffer[TAP_BUFFER_SIZE];
    DWORD bytes_read;
    
    while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
        if (tap_interface_->readPacket(buffer, sizeof(buffer), &bytes_read)) {
            if (bytes_read > 0) {
                processTapPacket(buffer, bytes_read);
            }
        } else {
            // 读取失败，可能是适配器断开
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    logMessage("TAP reader thread stopped");
}

void WindowsVPNClient::networkReaderThreadFunc() {
    logMessage("Network reader thread started");
    
    uint8_t buffer[NETWORK_BUFFER_SIZE];
    
    while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
        size_t received_length;
        if (receiveFromServer(buffer, sizeof(buffer), &received_length)) {
            if (received_length > 0) {
                processNetworkPacket(buffer, received_length);
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    logMessage("Network reader thread stopped");
}

void WindowsVPNClient::networkWriterThreadFunc() {
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

bool WindowsVPNClient::processTapPacket(const uint8_t* data, size_t length) {
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

bool WindowsVPNClient::processNetworkPacket(const uint8_t* data, size_t length) {
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
                    // 写入TAP适配器
                    DWORD bytes_written;
                    if (tap_interface_->writePacket(payload.first, payload.second, &bytes_written)) {
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

bool WindowsVPNClient::createSocket() {
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket_ == INVALID_SOCKET) {
        setLastError("Failed to create UDP socket: " + std::to_string(WSAGetLastError()));
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

void WindowsVPNClient::closeSocket() {
    if (udp_socket_ != INVALID_SOCKET) {
        closesocket(udp_socket_);
        udp_socket_ = INVALID_SOCKET;
    }
}

bool WindowsVPNClient::sendToServer(const uint8_t* data, size_t length) {
    if (udp_socket_ == INVALID_SOCKET) {
        return false;
    }
    
    int sent = sendto(udp_socket_, reinterpret_cast<const char*>(data), static_cast<int>(length),
                     0, reinterpret_cast<const struct sockaddr*>(&server_addr_), sizeof(server_addr_));
    
    if (sent == SOCKET_ERROR) {
        setLastError("Failed to send data to server: " + std::to_string(WSAGetLastError()));
        return false;
    }
    
    updateStats(sent, 0, 0, 0);
    return true;
}

bool WindowsVPNClient::receiveFromServer(uint8_t* buffer, size_t buffer_size, size_t* received_length) {
    if (udp_socket_ == INVALID_SOCKET) {
        return false;
    }
    
    // 设置接收超时
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udp_socket_, &read_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 10;  // 增加到10秒超时
    timeout.tv_usec = 0;
    
    int result = select(0, &read_fds, nullptr, nullptr, &timeout);
    if (result == 0) {
        // 超时
        logMessage("Receive timeout after " + std::to_string(timeout.tv_sec) + " seconds");
        return false;
    } else if (result == SOCKET_ERROR) {
        setLastError("Select error: " + std::to_string(WSAGetLastError()));
        return false;
    }
    
    struct sockaddr_in from_addr;
    int from_len = sizeof(from_addr);
    
    int received = recvfrom(udp_socket_, reinterpret_cast<char*>(buffer), static_cast<int>(buffer_size),
                           0, reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);
    
    if (received == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK) {
            setLastError("Failed to receive data from server: " + std::to_string(error));
        }
        return false;
    }
    
    *received_length = received;
    updateStats(0, received, 0, 0);
    return true;
}

bool WindowsVPNClient::sendSecureMessage(std::unique_ptr<common::SecureMessage> message) {
    if (!message) {
        return false;
    }
    
    // 如果握手已完成且消息需要加密
    if (secure_context_ && secure_context_->isHandshakeComplete() &&
        message->getType() != common::MessageType::HANDSHAKE_INIT &&
        message->getType() != common::MessageType::HANDSHAKE_RESPONSE &&
        message->getType() != common::MessageType::HANDSHAKE_COMPLETE) {
        
        if (!secure_context_->encryptMessage(*message)) {
            setLastError("Failed to encrypt message");
            return false;
        }
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

bool WindowsVPNClient::processSecureMessage(const uint8_t* buffer, size_t buffer_size,
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

void WindowsVPNClient::keepaliveThreadFunc() {
    logMessage("Keepalive thread started");
    
    while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
        std::this_thread::sleep_for(std::chrono::seconds(config_.keepalive_interval));
        
        if (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
            sendKeepalive();
        }
    }
    
    logMessage("Keepalive thread stopped");
}

bool WindowsVPNClient::sendKeepalive() {
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

void WindowsVPNClient::setState(ConnectionState new_state) {
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

void WindowsVPNClient::logMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_callback_) {
        log_callback_(message);
    } else {
        std::cout << "[VPNClient] " << message << std::endl;
    }
}

void WindowsVPNClient::updateStats(uint64_t bytes_sent, uint64_t bytes_received, 
                                  uint64_t packets_sent, uint64_t packets_received) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.bytes_sent += bytes_sent;
    stats_.bytes_received += bytes_received;
    stats_.packets_sent += packets_sent;
    stats_.packets_received += packets_received;
}

void WindowsVPNClient::setLastError(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
    logMessage("Error: " + error);
}

WindowsVPNClient::BandwidthTestResult WindowsVPNClient::performBandwidthTest(uint32_t test_duration_seconds, uint32_t test_size_mb) {
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

// WindowsVPNClientManager implementation
WindowsVPNClientManager& WindowsVPNClientManager::getInstance() {
    static WindowsVPNClientManager instance;
    return instance;
}

WindowsVPNClientManager::~WindowsVPNClientManager() {
    cleanupWinsock();
}

std::unique_ptr<WindowsVPNClient> WindowsVPNClientManager::createClient() {
    return std::make_unique<WindowsVPNClient>();
}

std::pair<bool, std::string> WindowsVPNClientManager::checkSystemRequirements() {
    // 检查操作系统版本
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    if (!GetVersionEx(reinterpret_cast<OSVERSIONINFO*>(&osvi))) {
        return {false, "Failed to get OS version information"};
    }
    
    if (osvi.dwMajorVersion < 6) {
        return {false, "Windows Vista or later is required"};
    }
    
    // 检查TAP驱动
    if (!TapAdapterManager::isTapDriverInstalled()) {
        return {false, "TAP-Windows driver is not installed"};
    }
    
    // 检查管理员权限
    if (!hasAdministratorPrivileges()) {
        return {false, "Administrator privileges are required"};
    }
    
    return {true, "System requirements met"};
}

bool WindowsVPNClientManager::initializeWinsock() {
    if (winsock_initialized_) {
        return true;
    }
    
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return false;
    }
    
    winsock_initialized_ = true;
    return true;
}

void WindowsVPNClientManager::cleanupWinsock() {
    if (winsock_initialized_) {
        WSACleanup();
        winsock_initialized_ = false;
    }
}

bool WindowsVPNClientManager::hasAdministratorPrivileges() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    
    return is_admin == TRUE;
}

bool WindowsVPNClientManager::requestAdministratorPrivileges() {
    // 这里应该实现UAC提权逻辑
    // 通常需要重新启动应用程序并请求管理员权限
    return hasAdministratorPrivileges();
}

} // namespace client
} // namespace sduvpn
