#include "client/windows_vpn_client.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace sduvpn {
namespace client {

WindowsVPNClient::WindowsVPNClient() 
    : tap_interface_(std::make_unique<WindowsTapInterface>()),
      crypto_context_(std::make_unique<crypto::CryptoContext>()),
      key_exchange_(std::make_unique<crypto::KeyExchangeProtocol>()) {
    
    // 初始化Winsock
    WindowsVPNClientManager::getInstance().initializeWinsock();
}

WindowsVPNClient::~WindowsVPNClient() {
    disconnect();
}

bool WindowsVPNClient::connect(const ConnectionConfig& config) {
    if (connection_state_.load() != ConnectionState::DISCONNECTED) {
        setLastError("Client is already connected or connecting");
        return false;
    }
    
    config_ = config;
    should_stop_.store(false);
    setState(ConnectionState::CONNECTING);
    
    // 启动连接线程
    connection_thread_ = std::thread(&WindowsVPNClient::connectionThreadFunc, this);
    
    return true;
}

void WindowsVPNClient::disconnect() {
    should_stop_.store(true);
    setState(ConnectionState::DISCONNECTING);
    
    // 等待所有线程结束
    if (connection_thread_.joinable()) {
        connection_thread_.join();
    }
    if (tap_reader_thread_.joinable()) {
        tap_reader_thread_.join();
    }
    if (network_reader_thread_.joinable()) {
        network_reader_thread_.join();
    }
    if (network_writer_thread_.joinable()) {
        network_writer_thread_.join();
    }
    if (keepalive_thread_.joinable()) {
        keepalive_thread_.join();
    }
    if (reconnect_thread_.joinable()) {
        reconnect_thread_.join();
    }
    
    // 清理资源
    closeSocket();
    if (tap_interface_) {
        tap_interface_->closeAdapter();
    }
    
    setState(ConnectionState::DISCONNECTED);
    logMessage("VPN connection disconnected");
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
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 2. 打开TAP适配器
        if (!tap_interface_->openAdapter(config_.tap_adapter_name)) {
            setLastError("Failed to open TAP adapter: " + tap_interface_->getLastError());
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 3. 执行握手协议
        setState(ConnectionState::AUTHENTICATING);
        if (!performHandshake()) {
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 4. 身份验证
        if (!authenticateWithServer()) {
            setState(ConnectionState::ERROR_STATE);
            return;
        }
        
        // 5. 设置隧道
        if (!setupTunnel()) {
            setState(ConnectionState::ERROR_STATE);
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
        setState(ConnectionState::ERROR_STATE);
    }
}

bool WindowsVPNClient::performHandshake() {
    logMessage("Performing handshake with server");
    
    // 生成密钥对
    if (key_exchange_->generateKeyPair() != crypto::CryptoError::SUCCESS) {
        setLastError("Failed to generate key pair");
        return false;
    }
    
    // 发送客户端公钥
    uint8_t client_public_key[crypto::ECDH_PUBLIC_KEY_SIZE];
    if (key_exchange_->getPublicKey(client_public_key) != crypto::CryptoError::SUCCESS) {
        setLastError("Failed to get public key");
        return false;
    }
    
    if (!sendToServer(client_public_key, sizeof(client_public_key))) {
        setLastError("Failed to send client public key");
        return false;
    }
    
    // 接收服务器公钥
    uint8_t server_public_key[crypto::ECDH_PUBLIC_KEY_SIZE];
    size_t received_length;
    if (!receiveFromServer(server_public_key, sizeof(server_public_key), &received_length) ||
        received_length != sizeof(server_public_key)) {
        setLastError("Failed to receive server public key");
        return false;
    }
    
    // 设置对方公钥并派生会话密钥
    if (key_exchange_->setPeerPublicKey(server_public_key) != crypto::CryptoError::SUCCESS) {
        setLastError("Failed to set peer public key");
        return false;
    }
    
    if (key_exchange_->deriveSessionKeys() != crypto::CryptoError::SUCCESS) {
        setLastError("Failed to derive session keys");
        return false;
    }
    
    // 初始化加密上下文
    auto session_keys = key_exchange_->getSessionKeys();
    if (!session_keys) {
        setLastError("Failed to get session keys");
        return false;
    }
    
    if (!crypto_context_->initialize(session_keys->encryption_key, sizeof(session_keys->encryption_key))) {
        setLastError("Failed to initialize crypto context");
        return false;
    }
    
    logMessage("Handshake completed successfully");
    return true;
}

bool WindowsVPNClient::authenticateWithServer() {
    logMessage("Authenticating with server");
    
    // 构建认证消息
    std::string auth_message = config_.username + ":" + config_.password;
    
    // 加密认证消息
    std::vector<uint8_t> encrypted_auth(auth_message.length() + 64); // 留出加密开销空间
    size_t encrypted_length;
    
    if (!crypto_context_->encrypt(
            reinterpret_cast<const uint8_t*>(auth_message.data()),
            auth_message.length(),
            encrypted_auth.data(),
            encrypted_auth.size(),
            &encrypted_length)) {
        setLastError("Failed to encrypt authentication message");
        return false;
    }
    
    // 发送加密的认证消息
    if (!sendToServer(encrypted_auth.data(), encrypted_length)) {
        setLastError("Failed to send authentication message");
        return false;
    }
    
    // 接收认证响应
    uint8_t response_buffer[256];
    size_t response_length;
    if (!receiveFromServer(response_buffer, sizeof(response_buffer), &response_length)) {
        setLastError("Failed to receive authentication response");
        return false;
    }
    
    // 解密响应
    std::vector<uint8_t> decrypted_response(response_length);
    size_t decrypted_length;
    
    if (!crypto_context_->decrypt(
            response_buffer,
            response_length,
            decrypted_response.data(),
            decrypted_response.size(),
            &decrypted_length)) {
        setLastError("Failed to decrypt authentication response");
        return false;
    }
    
    // 检查认证结果
    std::string response_str(reinterpret_cast<const char*>(decrypted_response.data()), decrypted_length);
    if (response_str.find("AUTH_SUCCESS") == std::string::npos) {
        setLastError("Authentication failed: " + response_str);
        return false;
    }
    
    // 解析虚拟IP地址
    size_t ip_pos = response_str.find("IP:");
    if (ip_pos != std::string::npos) {
        size_t ip_start = ip_pos + 3;
        size_t ip_end = response_str.find(" ", ip_start);
        if (ip_end == std::string::npos) {
            ip_end = response_str.length();
        }
        config_.virtual_ip = response_str.substr(ip_start, ip_end - ip_start);
    }
    
    logMessage("Authentication successful, assigned IP: " + config_.virtual_ip);
    return true;
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
    // 加密数据包
    std::vector<uint8_t> encrypted_packet(length + 64); // 留出加密开销空间
    size_t encrypted_length;
    
    if (!crypto_context_->encrypt(data, length, encrypted_packet.data(), 
                                 encrypted_packet.size(), &encrypted_length)) {
        return false;
    }
    
    // 添加到发送队列
    encrypted_packet.resize(encrypted_length);
    {
        std::lock_guard<std::mutex> lock(outbound_queue_mutex_);
        outbound_queue_.push(std::move(encrypted_packet));
    }
    outbound_queue_cv_.notify_one();
    
    updateStats(0, 0, 1, 0);
    return true;
}

bool WindowsVPNClient::processNetworkPacket(const uint8_t* data, size_t length) {
    // 解密数据包
    std::vector<uint8_t> decrypted_packet(length);
    size_t decrypted_length;
    
    if (!crypto_context_->decrypt(data, length, decrypted_packet.data(), 
                                 decrypted_packet.size(), &decrypted_length)) {
        return false;
    }
    
    // 写入TAP适配器
    DWORD bytes_written;
    if (!tap_interface_->writePacket(decrypted_packet.data(), decrypted_length, &bytes_written)) {
        return false;
    }
    
    updateStats(0, 0, 0, 1);
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
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    int result = select(0, &read_fds, nullptr, nullptr, &timeout);
    if (result == 0) {
        // 超时
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
    const std::string keepalive_msg = "KEEPALIVE";
    
    std::vector<uint8_t> encrypted_keepalive(keepalive_msg.length() + 64);
    size_t encrypted_length;
    
    if (!crypto_context_->encrypt(
            reinterpret_cast<const uint8_t*>(keepalive_msg.data()),
            keepalive_msg.length(),
            encrypted_keepalive.data(),
            encrypted_keepalive.size(),
            &encrypted_length)) {
        return false;
    }
    
    return sendToServer(encrypted_keepalive.data(), encrypted_length);
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
