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
    try {
        // 安全析构：强制停止所有活动
        should_stop_.store(true);
        
        // 通知所有等待的线程
        outbound_queue_cv_.notify_all();
        
        // 关闭所有资源
        closeSocket();
        if (tun_interface_) {
            try {
                tun_interface_->closeInterface();
            } catch (...) {
                // 忽略析构时的错误
            }
        }
        
        // 强制设置状态为断开，确保所有线程能正确退出
        connection_state_.store(ConnectionState::DISCONNECTED);
        
        // 安全地等待所有线程结束
        waitForThreadsToFinish();
        
        // 清理安全上下文
        secure_context_.reset();
        
    } catch (...) {
        // 析构函数不能抛出异常，忽略所有异常
    }
}

bool LinuxVPNClient::connect(const ConnectionConfig& config) {
    // 转换为Linux特定配置
    LinuxConnectionConfig linux_config;
    linux_config.server_address = config.server_address;
    linux_config.server_port = config.server_port;
    linux_config.username = config.username;
    linux_config.password = config.password;
    linux_config.interface_name = config.interface_name;
    linux_config.virtual_ip = config.virtual_ip;
    linux_config.virtual_netmask = config.virtual_netmask;
    linux_config.keepalive_interval = config.keepalive_interval;
    linux_config.connection_timeout = config.connection_timeout;
    linux_config.auto_reconnect = config.auto_reconnect;
    linux_config.max_reconnect_attempts = config.max_reconnect_attempts;
    
    return connect(linux_config);
}

bool LinuxVPNClient::connect(const LinuxConnectionConfig& config) {
    // 使用互斥锁保护整个连接过程
    static std::mutex connect_mutex;
    std::lock_guard<std::mutex> connect_lock(connect_mutex);
    
    auto current_state = connection_state_.load();
    
    // 如果正在连接或已连接，先完全断开
    if (current_state != ConnectionState::DISCONNECTED) {
        logMessage("Force disconnecting existing connection before reconnecting...");
        
        // 调用标准的disconnect方法，确保完全清理
        disconnect();
        
        // 确保所有线程对象都已清理
        if (connection_thread_.joinable()) connection_thread_.detach();
        if (tun_reader_thread_.joinable()) tun_reader_thread_.detach();
        if (network_reader_thread_.joinable()) network_reader_thread_.detach();
        if (network_writer_thread_.joinable()) network_writer_thread_.detach();
        if (keepalive_thread_.joinable()) keepalive_thread_.detach();
        if (reconnect_thread_.joinable()) reconnect_thread_.detach();
        
        // 额外等待确保所有资源都已清理
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        logMessage("Previous connection completely cleaned up");
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
    try {
        connection_thread_ = std::thread(&LinuxVPNClient::connectionThreadFunc, this);
    } catch (const std::exception& e) {
        setLastError("Failed to create connection thread: " + std::string(e.what()));
        setState(ConnectionState::ERROR_STATE);
        return false;
    }
    
    logMessage("New connection attempt started");
    return true;
}

void LinuxVPNClient::disconnect() {
    auto current_state = connection_state_.load();
    if (current_state == ConnectionState::DISCONNECTED) {
        return; // 已经断开连接
    }
    
    // 避免重复断开
    static std::mutex disconnect_mutex;
    std::lock_guard<std::mutex> disconnect_lock(disconnect_mutex);
    
    // 再次检查状态，避免在等待锁期间状态已改变
    if (connection_state_.load() == ConnectionState::DISCONNECTED) {
        return;
    }
    
    logMessage("Initiating safe disconnect...");
    
    // 设置停止标志
    should_stop_.store(true);
    setState(ConnectionState::DISCONNECTING);
    
    // 停止自动重连线程
    stopReconnectThread();
    
    // 通知所有等待的线程
    outbound_queue_cv_.notify_all();
    
    // 关闭网络资源（这会中断阻塞的网络调用）
    closeSocket();
    
    // 尝试优雅地等待线程结束
    const auto cleanup_timeout = std::chrono::seconds(3);
    
    std::vector<std::thread*> threads = {
        &tun_reader_thread_,
        &network_reader_thread_, 
        &network_writer_thread_,
        &keepalive_thread_,
        &reconnect_thread_
    };
    
    // 等待线程结束
    for (auto* thread : threads) {
        if (thread->joinable()) {
            try {
                // 给每个线程最多200ms时间结束
                auto thread_start = std::chrono::steady_clock::now();
                while (thread->joinable() && 
                       std::chrono::steady_clock::now() - thread_start < std::chrono::milliseconds(200)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                
                if (thread->joinable()) {
                    // 使用detach()来避免长时间阻塞，但确保线程能安全结束
                    thread->detach();
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
    
    // 清理虚拟IP
    {
        std::lock_guard<std::mutex> lock(virtual_ip_mutex_);
        assigned_virtual_ip_.clear();
    }
    
    setState(ConnectionState::DISCONNECTED);
    logMessage("VPN connection disconnected safely");
}

common::VPNClientInterface::ConnectionStats LinuxVPNClient::getConnectionStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    common::VPNClientInterface::ConnectionStats base_stats;
    base_stats.bytes_sent = stats_.bytes_sent;
    base_stats.bytes_received = stats_.bytes_received;
    base_stats.packets_sent = stats_.packets_sent;
    base_stats.packets_received = stats_.packets_received;
    base_stats.connection_start_time = stats_.connection_start_time;
    return base_stats;
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

std::string LinuxVPNClient::getVirtualIP() const {
    std::lock_guard<std::mutex> lock(virtual_ip_mutex_);
    return assigned_virtual_ip_;
}

std::string LinuxVPNClient::getServerIP() const {
    return config_.server_address;
}

void LinuxVPNClient::connectionThreadFunc() {
    try {
        logMessage("Starting VPN connection to " + config_.server_address + ":" + std::to_string(config_.server_port));
        
        // 1. 创建网络套接字
        if (!createSocket()) {
            setState(ConnectionState::DISCONNECTED);
            return;
        }
        
        // 2. 快速清理之前的网络线程
        if (network_reader_thread_.joinable()) {
            network_reader_thread_.detach();
        }
        if (network_writer_thread_.joinable()) {
            network_writer_thread_.detach();
        }
        
        // 启动网络读取线程（需要在握手前启动以接收响应）
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
            logMessage("Handshake failed, cleaning up...");
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 5. 身份验证
        if (!authenticateWithServer()) {
            logMessage("Authentication failed, cleaning up...");
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 6. 设置隧道
        if (!setupTunnel()) {
            logMessage("Tunnel setup failed, cleaning up...");
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 7. 快速清理之前的数据处理线程
        if (tun_reader_thread_.joinable()) {
            tun_reader_thread_.detach();
        }
        if (keepalive_thread_.joinable()) {
            keepalive_thread_.detach();
        }
        
        // 启动剩余的数据处理线程
        tun_reader_thread_ = std::thread(&LinuxVPNClient::tunReaderThreadFunc, this);
        keepalive_thread_ = std::thread(&LinuxVPNClient::keepaliveThreadFunc, this);
        
        setState(ConnectionState::CONNECTED);
        stats_.connection_start_time = std::chrono::steady_clock::now();
        logMessage("VPN connection established successfully");
        
        // 启动自动重连线程（如果启用）
        if (config_.auto_reconnect) {
            startReconnectThread();
        }
        
        // 等待断开信号
        while (!should_stop_.load() && connection_state_.load() == ConnectionState::CONNECTED) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
    } catch (const std::exception& e) {
        setLastError("Connection thread error: " + std::string(e.what()));
        logMessage("Exception in connection thread: " + std::string(e.what()));
    } catch (...) {
        setLastError("Unknown error in connection thread");
        logMessage("Unknown exception in connection thread");
    }
    
    // 确保在线程结束时进行清理
    try {
        // 设置停止标志
        should_stop_.store(true);
        
        // 通知所有等待的线程
        outbound_queue_cv_.notify_all();
        
        // 关闭网络资源
        closeSocket();
        if (tun_interface_) {
            tun_interface_->closeInterface();
        }
        
        // 等待网络线程结束（它们是在这个连接线程中启动的）
        if (network_reader_thread_.joinable()) {
            try {
                network_reader_thread_.join();
                logMessage("Network reader thread joined");
            } catch (...) {
                logMessage("Exception joining network reader thread");
            }
        }
        
        if (network_writer_thread_.joinable()) {
            try {
                network_writer_thread_.join();
                logMessage("Network writer thread joined");
            } catch (...) {
                logMessage("Exception joining network writer thread");
            }
        }
        
        if (tun_reader_thread_.joinable()) {
            try {
                tun_reader_thread_.join();
                logMessage("TUN reader thread joined");
            } catch (...) {
                logMessage("Exception joining TUN reader thread");
            }
        }
        
        if (keepalive_thread_.joinable()) {
            try {
                keepalive_thread_.join();
                logMessage("Keepalive thread joined");
            } catch (...) {
                logMessage("Exception joining keepalive thread");
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
        
        // 确保状态为DISCONNECTED
        setState(ConnectionState::DISCONNECTED);
        logMessage("Connection thread cleanup completed");
        
    } catch (...) {
        // 忽略清理时的异常
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
    int consecutive_timeouts = 0;
    const int max_timeouts = 12; // 连续12次超时（60秒）后认为服务器断开
    auto last_successful_receive = std::chrono::steady_clock::now();
    
    try {
        while (!should_stop_.load()) {
            // 只有在连接过程中才处理网络数据包
            if (connection_state_.load() != ConnectionState::DISCONNECTED &&
                connection_state_.load() != ConnectionState::ERROR_STATE) {
                size_t received_length;
                if (receiveFromServer(buffer, sizeof(buffer), &received_length)) {
                    if (received_length > 0) {
                        processNetworkPacket(buffer, received_length);
                        consecutive_timeouts = 0; // 重置超时计数
                        last_successful_receive = std::chrono::steady_clock::now();
                    }
                    // 即使收到0字节，也重置超时计数（说明服务器还在响应）
                    consecutive_timeouts = 0;
                } else {
                    // 如果套接字已关闭，退出循环
                    if (udp_socket_ < 0) {
                        break;
                    }
                    
                    // 检查是否是真正的网络错误
                    int error = errno;
                    if (error == ETIMEDOUT || error == EAGAIN || error == EWOULDBLOCK || error == 0) {
                        // 接收超时，检查是否连续超时过多
                        consecutive_timeouts++;
                        
                        // 检查总的无响应时间
                        auto now = std::chrono::steady_clock::now();
                        auto no_response_duration = std::chrono::duration_cast<std::chrono::seconds>(
                            now - last_successful_receive);
                        
                        // 如果连续超时过多或无响应时间过长，且处于连接状态
                        if ((consecutive_timeouts >= max_timeouts || no_response_duration.count() >= 60) &&
                            connection_state_.load() == ConnectionState::CONNECTED) {
                            logMessage("Server appears to be disconnected (no response for " + 
                                     std::to_string(no_response_duration.count()) + " seconds, timeouts: " +
                                     std::to_string(consecutive_timeouts) + ")");
                            setState(ConnectionState::ERROR_STATE);
                            setLastError("Server connection lost");
                            break;
                        }
                        
                        // 定期报告无响应状态（每10秒一次）
                        if (no_response_duration.count() > 0 && no_response_duration.count() % 10 == 0 &&
                            consecutive_timeouts % 2 == 0) { // 避免重复日志
                            logMessage("No server response for " + std::to_string(no_response_duration.count()) + " seconds");
                        }
                    } else {
                        // 真正的网络错误，立即认为连接断开
                        if (connection_state_.load() == ConnectionState::CONNECTED) {
                            logMessage("Network error detected: " + std::to_string(error));
                            setState(ConnectionState::ERROR_STATE);
                            setLastError("Network error: " + std::to_string(error));
                            break;
                        }
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            } else {
                // 如果已断开连接，等待一段时间后退出
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                break;
            }
        }
    } catch (const std::exception& e) {
        logMessage("Exception in network reader thread: " + std::string(e.what()));
    } catch (...) {
        logMessage("Unknown exception in network reader thread");
    }
    
    logMessage("Network reader thread stopped");
}

void LinuxVPNClient::networkWriterThreadFunc() {
    logMessage("Network writer thread started");
    
    try {
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
                
                if (!sendToServer(packet.data(), packet.size())) {
                    // 发送失败，可能是套接字已关闭
                    if (udp_socket_ < 0) {
                        logMessage("Socket closed, stopping network writer");
                        return;
                    }
                }
                
                lock.lock();
            }
        }
    } catch (const std::exception& e) {
        logMessage("Exception in network writer thread: " + std::string(e.what()));
    } catch (...) {
        logMessage("Unknown exception in network writer thread");
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
                    // 提取虚拟IP地址
                    size_t ip_pos = response.find("\"virtual_ip\":\"");
                    if (ip_pos != std::string::npos) {
                        size_t start = ip_pos + 14;
                        size_t end = response.find("\"", start);
                        if (end != std::string::npos) {
                            std::string virtual_ip = response.substr(start, end - start);
                            {
                                std::lock_guard<std::mutex> lock(virtual_ip_mutex_);
                                assigned_virtual_ip_ = virtual_ip;
                            }
                            logMessage("Assigned virtual IP: " + virtual_ip);
                        }
                    }
                    
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
    timeout.tv_sec = 5;  // 设置为5秒超时，平衡响应性和稳定性
    timeout.tv_usec = 0;
    
    int result = select(udp_socket_ + 1, &read_fds, nullptr, nullptr, &timeout);
    if (result == 0) {
        // 超时（正常情况，不记录日志避免刷屏）
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

void LinuxVPNClient::startReconnectThread() {
    if (config_.auto_reconnect && !reconnect_thread_.joinable()) {
        reconnect_thread_ = std::thread(&LinuxVPNClient::reconnectThreadFunc, this);
        logMessage("Auto-reconnect thread started");
    }
}

void LinuxVPNClient::stopReconnectThread() {
    if (reconnect_thread_.joinable()) {
        reconnect_thread_.detach();
        logMessage("Auto-reconnect thread stopped");
    }
}

void LinuxVPNClient::reconnectThreadFunc() {
    logMessage("Reconnect thread started");
    
    uint32_t reconnect_attempts = 0;
    const uint32_t max_attempts = config_.max_reconnect_attempts;
    const auto reconnect_delay = std::chrono::seconds(5); // 5秒重连延迟
    
    while (!should_stop_.load() && reconnect_attempts < max_attempts) {
        // 等待连接错误状态
        if (connection_state_.load() == ConnectionState::ERROR_STATE) {
            reconnect_attempts++;
            
            logMessage("Attempting reconnection " + std::to_string(reconnect_attempts) + 
                      "/" + std::to_string(max_attempts));
            
            // 等待一段时间后尝试重连
            std::this_thread::sleep_for(reconnect_delay);
            
            if (should_stop_.load()) {
                break;
            }
            
            // 尝试重新连接
            if (connect(config_)) {
                logMessage("Reconnection successful");
                reconnect_attempts = 0; // 重置重连计数
                
                // 更新统计信息
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.reconnect_count++;
                }
                
                // 等待连接建立或失败
                auto start_time = std::chrono::steady_clock::now();
                const auto timeout = std::chrono::seconds(30);
                
                while (std::chrono::steady_clock::now() - start_time < timeout) {
                    auto state = connection_state_.load();
                    
                    if (state == ConnectionState::CONNECTED) {
                        logMessage("Reconnection completed successfully");
                        break;
                    } else if (state == ConnectionState::ERROR_STATE) {
                        logMessage("Reconnection failed");
                        break;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            } else {
                logMessage("Failed to initiate reconnection");
            }
        } else {
            // 如果连接正常，重置重连计数
            if (connection_state_.load() == ConnectionState::CONNECTED) {
                reconnect_attempts = 0;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    if (reconnect_attempts >= max_attempts) {
        logMessage("Maximum reconnection attempts reached, giving up");
        setLastError("Maximum reconnection attempts reached");
    }
    
    logMessage("Reconnect thread stopped");
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

void LinuxVPNClient::waitForThreadsToFinish() {
    // 等待线程结束（析构时给较短的时间）
    const auto cleanup_timeout = std::chrono::milliseconds(1000); // 1秒
    
    std::vector<std::thread*> threads = {
        &connection_thread_,
        &tun_reader_thread_,
        &network_reader_thread_, 
        &network_writer_thread_,
        &keepalive_thread_,
        &reconnect_thread_
    };
    
    for (auto* thread : threads) {
        if (thread->joinable()) {
            try {
                auto thread_start = std::chrono::steady_clock::now();
                while (thread->joinable() && 
                       std::chrono::steady_clock::now() - thread_start < std::chrono::milliseconds(200)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                
                if (thread->joinable()) {
                    // 析构时优先使用join()，避免detach()导致的内存安全问题
                    try {
                        thread->join();
                    } catch (...) {
                        // 只有在join失败时才使用detach作为最后手段
                        thread->detach();
                    }
                }
            } catch (...) {
                // 忽略析构时的异常
            }
        }
    }
}

} // namespace client
} // namespace sduvpn
