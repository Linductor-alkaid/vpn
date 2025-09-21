#include "server/vpn_server.h"
#include "server/client_session.h"
#include "server/tun_interface.h"
#include "server/server_config.h"
#include "server/packet_router.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

namespace sduvpn {
namespace server {

VPNServer::VPNServer() 
    : start_time_(std::chrono::steady_clock::now()) {
    std::memset(&stats_, 0, sizeof(stats_));
    
#ifdef _WIN32
    // 初始化Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup 失败: " << result << std::endl;
    }
#endif
}

VPNServer::~VPNServer() {
    stop();
    
#ifdef _WIN32
    WSACleanup();
#endif
}

bool VPNServer::start(const ServerConfig& config) {
    if (running_.load()) {
        std::cerr << "Server is already running" << std::endl;
        return false;
    }
    
    // Validate configuration
    if (!config.validate()) {
        std::cerr << "Invalid server configuration" << std::endl;
        return false;
    }
    
    // 保存配置
    config_ = std::make_unique<ServerConfig>(config);
    listen_port_ = config.getListenPort();
    
    std::cout << "Starting SDUVPN server..." << std::endl;
    std::cout << "Listen port: " << listen_port_ << std::endl;
    std::cout << "Virtual network: " << config.getVirtualNetwork() << "/" << config.getVirtualNetmask() << std::endl;
    std::cout << "Max clients: " << config.getMaxClients() << std::endl;
    
    // Create UDP socket
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_ < 0) {
        std::cerr << "Failed to create UDP socket" << std::endl;
        return false;
    }
    
    // 设置套接字选项
    int reuse = 1;
    if (setsockopt(udp_socket_, SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&reuse), sizeof(reuse)) < 0) {
        std::cerr << "Failed to set SO_REUSEADDR" << std::endl;
    }
    
    // 绑定地址
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(listen_port_);
    
    if (config.getBindAddress() == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, config.getBindAddress().c_str(), &server_addr.sin_addr) != 1) {
            std::cerr << "Invalid bind address: " << config.getBindAddress() << std::endl;
            closeSocket();
            return false;
        }
    }
    
    if (bind(udp_socket_, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
#ifdef _WIN32
        std::cerr << "Failed to bind address: " << WSAGetLastError() << std::endl;
#else
        std::cerr << "Failed to bind address: " << strerror(errno) << std::endl;
#endif
        closeSocket();
        return false;
    }
    
    // Create TUN interface
    tun_interface_ = std::make_unique<TunTapInterface>();
    if (!tun_interface_->createTun(config.getTunInterfaceName())) {
        std::cerr << "Failed to create TUN interface" << std::endl;
        closeSocket();
        return false;
    }
    
    // Configure TUN interface - set server IP as gateway (.1)
    std::string server_ip = config.getVirtualNetwork();
    // Convert network address to gateway address (change last octet to 1)
    size_t last_dot = server_ip.find_last_of('.');
    if (last_dot != std::string::npos) {
        server_ip = server_ip.substr(0, last_dot + 1) + "1";
    }
    
    if (!tun_interface_->setIPAddress(server_ip, config.getVirtualNetmask())) {
        std::cerr << "Failed to set TUN interface IP address to " << server_ip << std::endl;
        closeSocket();
        return false;
    }
    
    std::cout << "TUN interface configured with IP: " << server_ip << "/" << config.getVirtualNetmask() << std::endl;
    
    if (!tun_interface_->bringUp()) {
        std::cerr << "Failed to bring up TUN interface" << std::endl;
        closeSocket();
        return false;
    }
    
    // Set TUN interface to non-blocking mode
    tun_interface_->setNonBlocking(true);
    
    // Initialize packet router
    packet_router_ = std::make_unique<PacketRouter>();
    if (!packet_router_->initialize(config.getVirtualNetwork(), config.getVirtualNetmask())) {
        std::cerr << "Failed to initialize packet router" << std::endl;
        closeSocket();
        return false;
    }
    
    packet_router_->setDebugMode(true);  // 临时启用调试模式
    
    // Initialize IP address pool
    if (!initializeIPPool()) {
        std::cerr << "Failed to initialize IP address pool" << std::endl;
        closeSocket();
        return false;
    }
    
    // Set running flags
    running_.store(true);
    should_stop_.store(false);
    
    // Start worker threads
    network_thread_ = std::thread(&VPNServer::networkThreadFunc, this);
    tun_thread_ = std::thread(&VPNServer::tunThreadFunc, this);
    cleanup_thread_ = std::thread(&VPNServer::cleanupThreadFunc, this);
    
    std::cout << "SDUVPN server started successfully" << std::endl;
    return true;
}

void VPNServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "Stopping SDUVPN server..." << std::endl;
    
    // Set stop flags
    should_stop_.store(true);
    running_.store(false);
    
    // Wait for threads to finish
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    // Close network socket
    closeSocket();
    
    // Close TUN interface
    if (tun_interface_) {
        tun_interface_->close();
        tun_interface_.reset();
    }
    
    // Clean up client sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
        ip_to_client_.clear();
    }
    
    // Clean up router
    packet_router_.reset();
    config_.reset();
    
    std::cout << "SDUVPN server stopped" << std::endl;
}

size_t VPNServer::getClientCount() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // 只统计真正活跃的客户端（排除DISCONNECTED状态）
    size_t active_count = 0;
    for (const auto& pair : sessions_) {
        if (pair.second->getState() != SessionState::DISCONNECTED) {
            active_count++;
        }
    }
    
    return active_count;
}

size_t VPNServer::getTotalSessionCount() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.size();
}

VPNServer::Statistics VPNServer::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    Statistics stats = stats_;
    stats.active_clients = static_cast<uint32_t>(getClientCount());
    
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
    stats.uptime_seconds = static_cast<uint64_t>(uptime.count());
    
    return stats;
}

void VPNServer::networkThreadFunc() {
    std::cout << "Network thread started" << std::endl;
    
    const size_t buffer_size = config_->getReceiveBufferSize();
    std::vector<uint8_t> buffer(buffer_size);
    
    while (!should_stop_.load()) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int bytes_received = recvfrom(udp_socket_, 
                                     reinterpret_cast<char*>(buffer.data()), 
                                     static_cast<int>(buffer_size), 0,
                                     reinterpret_cast<struct sockaddr*>(&client_addr), 
                                     &addr_len);
        
        if (bytes_received > 0) {
            handleClientMessage(client_addr, buffer.data(), bytes_received);
            
            // 更新统计信息
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.bytes_received += bytes_received;
            stats_.packets_received++;
        } else if (bytes_received < 0) {
#ifdef _WIN32
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != WSAEINTR) {
                if (!should_stop_.load()) {
                    std::cerr << "Failed to receive data: " << error << std::endl;
                }
                break;
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                if (!should_stop_.load()) {
                    std::cerr << "Failed to receive data: " << strerror(errno) << std::endl;
                }
                break;
            }
#endif
        }
        
        // Avoid high CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "Network thread ended" << std::endl;
}

void VPNServer::tunThreadFunc() {
    std::cout << "TUN thread started" << std::endl;
    
    const size_t buffer_size = 2048;
    std::vector<uint8_t> buffer(buffer_size);
    
    while (!should_stop_.load()) {
        if (!tun_interface_ || !tun_interface_->isOpen()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        int bytes_read = tun_interface_->readPacket(buffer.data(), buffer_size);
        if (bytes_read > 0) {
            handleTunPacket(buffer.data(), bytes_read);
        } else if (bytes_read < 0) {
            // Normal case in non-blocking mode
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    std::cout << "TUN thread ended" << std::endl;
}

void VPNServer::cleanupThreadFunc() {
    std::cout << "Cleanup thread started" << std::endl;
    
    while (!should_stop_.load()) {
        cleanupInactiveSessions();
        
        // Cleanup every 1 second for maximum responsiveness
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "Cleanup thread ended" << std::endl;
}

void VPNServer::handleClientMessage(const struct sockaddr_in& client_addr, 
                                   const uint8_t* data, size_t length) {
    // Find or create client session
    SessionPtr session = findOrCreateSession(client_addr);
    if (!session) {
        return;
    }
    
    // Update session activity time
    session->updateLastActivity();
    
    // 处理安全消息
    std::unique_ptr<common::SecureMessage> message;
    if (!session->processSecureMessage(data, length, message)) {
        std::cerr << "Failed to process secure message from client " 
                  << session->getClientId() << " (data length: " << length << ")" << std::endl;
        return;
    }
    
    // 只记录非数据包和非心跳包的消息，避免刷屏
    if (message->getType() != common::MessageType::DATA_PACKET && 
        message->getType() != common::MessageType::KEEPALIVE) {
        std::cout << "Received message from client " << session->getClientId() 
                  << ", type: " << static_cast<int>(message->getType())
                  << ", length: " << length << " bytes" << std::endl;
    }
    
    // 根据消息类型处理（只记录非数据包消息）
    if (message->getType() != common::MessageType::DATA_PACKET) {
        std::cout << "Processing message type: " << static_cast<int>(message->getType()) 
                  << " from client " << session->getClientId() 
                  << " (state: " << static_cast<int>(session->getState()) << ")" << std::endl;
    }
    
    switch (message->getType()) {
        case common::MessageType::HANDSHAKE_INIT:
            handleHandshakeInit(session, message.get());
            break;
            
        case common::MessageType::HANDSHAKE_COMPLETE:
            handleHandshakeComplete(session, message.get());
            break;
            
        case common::MessageType::AUTH_REQUEST:
            handleAuthRequest(session, message.get());
            break;
            
        case common::MessageType::DATA_PACKET:
            handleDataPacket(session, message.get());
            break;
            
        case common::MessageType::KEEPALIVE:
            handleKeepAlive(session, message.get());
            break;
            
        case common::MessageType::DISCONNECT:
            handleDisconnect(session, message.get());
            break;
            
        default:
            std::cerr << "Unknown message type: " 
                      << static_cast<int>(message->getType()) << std::endl;
            break;
    }
}

void VPNServer::handleHandshakeInit(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message) {
        return;
    }
    
    std::cout << "Handling handshake init from client " << session->getClientId() 
              << ", current state: " << static_cast<int>(session->getState()) << std::endl;
    
    // 初始化安全协议上下文
    if (!session->initializeSecureProtocol()) {
        std::cerr << "Failed to initialize secure protocol for client " 
                  << session->getClientId() << std::endl;
        return;
    }
    
    // 解析握手初始化消息
    auto payload = message->getPayload();
    std::cout << "Handshake init payload size: " << payload.second 
              << ", expected: " << sizeof(common::HandshakeInitMessage) << std::endl;
    
    if (payload.second < sizeof(common::HandshakeInitMessage)) {
        std::cerr << "Invalid handshake init message size" << std::endl;
        return;
    }
    
    const common::HandshakeInitMessage* init_msg = 
        reinterpret_cast<const common::HandshakeInitMessage*>(payload.first);
    
    // 处理握手初始化
    common::HandshakeResponseMessage response_msg;
    if (!session->handleHandshakeInit(*init_msg, response_msg)) {
        std::cerr << "Failed to handle handshake init" << std::endl;
        return;
    }
    
    // 创建响应消息
    auto response = session->createSecureMessage(common::MessageType::HANDSHAKE_RESPONSE);
    if (!response) {
        std::cerr << "Failed to create handshake response message" << std::endl;
        return;
    }
    
    response->setPayload(reinterpret_cast<const uint8_t*>(&response_msg), 
                        sizeof(response_msg));
    
    // 发送响应
    sendSecureMessage(session, std::move(response));
}

void VPNServer::handleHandshakeComplete(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message) {
        return;
    }
    
    std::cout << "Handling handshake complete from client " << session->getClientId() << std::endl;
    
    // 解析握手完成消息
    auto payload = message->getPayload();
    if (payload.second < sizeof(common::HandshakeCompleteMessage)) {
        std::cerr << "Invalid handshake complete message size" << std::endl;
        return;
    }
    
    const common::HandshakeCompleteMessage* complete_msg = 
        reinterpret_cast<const common::HandshakeCompleteMessage*>(payload.first);
    
    // 完成握手
    if (!session->completeHandshake(*complete_msg)) {
        std::cerr << "Failed to complete handshake" << std::endl;
        return;
    }
    
    std::cout << "Handshake completed successfully for client " 
              << session->getClientId() << std::endl;
}

void VPNServer::handleAuthRequest(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message) {
        return;
    }
    
    std::cout << "Handling auth request from client " << session->getClientId() << std::endl;
    
    // 解析认证请求数据
    auto payload = message->getPayload();
    if (!payload.first || payload.second == 0) {
        std::cerr << "Empty auth request from client " << session->getClientId() << std::endl;
        return;
    }
    
    std::string auth_data(reinterpret_cast<const char*>(payload.first), payload.second);
    std::cout << "Auth data length: " << payload.second << std::endl;
    std::cout << "Message encrypted: " << (message->isEncrypted() ? "yes" : "no") << std::endl;
    std::cout << "Auth data: " << auth_data << std::endl;
    
    // 简单的JSON解析（提取用户名和密码）
    std::string username, password, client_version = "SDUVPN Client v1.0";
    
    // 解析username
    size_t username_pos = auth_data.find("\"username\":\"");
    if (username_pos != std::string::npos) {
        size_t start = username_pos + 12;
        size_t end = auth_data.find("\"", start);
        if (end != std::string::npos) {
            username = auth_data.substr(start, end - start);
        }
    }
    
    // 解析password
    size_t password_pos = auth_data.find("\"password\":\"");
    if (password_pos != std::string::npos) {
        size_t start = password_pos + 12;
        size_t end = auth_data.find("\"", start);
        if (end != std::string::npos) {
            password = auth_data.substr(start, end - start);
        }
    }
    
    // 解析client_version
    size_t version_pos = auth_data.find("\"client_version\":\"");
    if (version_pos != std::string::npos) {
        size_t start = version_pos + 18;
        size_t end = auth_data.find("\"", start);
        if (end != std::string::npos) {
            client_version = auth_data.substr(start, end - start);
        }
    }
    
    std::cout << "Parsed credentials - Username: " << username << ", Version: " << client_version << std::endl;
    
    // 进行认证
    if (session->authenticate(username, password, client_version, config_.get())) {
        // 检查会话是否已经有分配的IP
        std::string virtual_ip = session->getVirtualIP();
        if (virtual_ip.empty()) {
            // 分配新的虚拟IP
            virtual_ip = allocateVirtualIP();
            if (virtual_ip.empty()) {
                std::cerr << "Failed to allocate virtual IP for client " << session->getClientId() << std::endl;
                auto error_response = session->createSecureMessage(common::MessageType::ERROR_RESPONSE);
                if (error_response) {
                    std::string error_msg = "{\"error\":\"no_available_ip\"}";
                    error_response->setPayload(reinterpret_cast<const uint8_t*>(error_msg.c_str()), 
                                             error_msg.length());
                    sendSecureMessage(session, std::move(error_response));
                }
                return;
            }
            session->assignVirtualIP(virtual_ip);
            
            // 将客户端路由添加到路由器
            if (packet_router_) {
                packet_router_->addClientRoute(session->getClientId(), virtual_ip, session);
                std::cout << "Added client route: " << virtual_ip << " -> client " << session->getClientId() << std::endl;
            }
        } else {
            // 重用现有IP，需要确保IP仍然被分配给该客户端
            std::cout << "Reusing existing virtual IP: " << virtual_ip << " for client " << session->getClientId() << std::endl;
            
            // 确保路由存在
            if (packet_router_) {
                packet_router_->addClientRoute(session->getClientId(), virtual_ip, session);
                std::cout << "Re-added client route: " << virtual_ip << " -> client " << session->getClientId() << std::endl;
            }
        }
        
        // 创建认证响应
        auto response = session->createSecureMessage(common::MessageType::AUTH_RESPONSE);
        if (response) {
            std::string auth_response = "{\"status\":\"success\",\"virtual_ip\":\"" + virtual_ip + "\"}";
            response->setPayload(reinterpret_cast<const uint8_t*>(auth_response.c_str()), 
                               auth_response.length());
            
            std::cout << "Sending auth response: " << auth_response << std::endl;
            if (sendSecureMessage(session, std::move(response))) {
                std::cout << "Auth response sent successfully" << std::endl;
                
                // 认证响应发送成功后，将状态设置为ACTIVE
                session->setState(SessionState::ACTIVE);
                std::cout << "Client " << session->getClientId() << " state set to ACTIVE" << std::endl;
            } else {
                std::cout << "Failed to send auth response" << std::endl;
            }
        } else {
            std::cout << "Failed to create auth response message" << std::endl;
        }
        
        std::cout << "Client " << session->getClientId() 
                  << " authenticated successfully, assigned IP: " << virtual_ip << std::endl;
    } else {
        // 认证失败
        auto response = session->createSecureMessage(common::MessageType::ERROR_RESPONSE);
        if (response) {
            std::string error_response = "{\"error\":\"authentication_failed\"}";
            response->setPayload(reinterpret_cast<const uint8_t*>(error_response.c_str()), 
                               error_response.length());
            
            sendSecureMessage(session, std::move(response));
        }
        
        std::cerr << "Authentication failed for client " << session->getClientId() << std::endl;
    }
}

void VPNServer::handleDataPacket(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message || session->getState() != SessionState::ACTIVE) {
        return;
    }
    
    // 获取解密后的数据包
    auto payload = message->getPayload();
    if (payload.first && payload.second > 0) {
        // 使用路由器处理数据包
        if (packet_router_) {
            auto routing_result = packet_router_->routePacket(payload.first, payload.second);
            
            switch (routing_result.action) {
                case PacketRouter::RoutingResult::TO_CLIENT:
                    if (routing_result.target_session) {
                        // 转发到目标客户端（需要重新加密）
                        forwardPacketToClient(routing_result.target_session, payload.first, payload.second);
                    }
                    break;
                    
                case PacketRouter::RoutingResult::TO_TUN:
                    // 写入TUN接口
                    if (tun_interface_) {
                        tun_interface_->writePacket(payload.first, payload.second);
                    }
                    break;
                    
                case PacketRouter::RoutingResult::BROADCAST:
                    // 广播到所有客户端
                    broadcastEncryptedPacket(payload.first, payload.second, session->getClientId());
                    break;
                    
                case PacketRouter::RoutingResult::DROP:
                default:
                    // 丢弃数据包
                    break;
            }
        }
    }
}

void VPNServer::handleKeepAlive(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message) {
        return;
    }
    
    // 显式更新活跃时间（确保心跳包能重置超时计时器）
    session->updateLastActivity();
    
    // 记录心跳包接收时间以便调试
    auto now = std::chrono::steady_clock::now();
    static std::unordered_map<ClientId, std::chrono::steady_clock::time_point> last_keepalive_time;
    
    auto it = last_keepalive_time.find(session->getClientId());
    if (it != last_keepalive_time.end()) {
        auto interval = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        // 只在间隔异常时记录日志
        if (interval.count() > 5) {
            std::cout << "Keepalive from client " << session->getClientId() 
                      << " (long interval: " << interval.count() << "s)" << std::endl;
        }
    } else {
        std::cout << "First keepalive from client " << session->getClientId() << std::endl;
    }
    last_keepalive_time[session->getClientId()] = now;
    
    // 检查会话状态是否适合发送响应
    if (session->getState() != SessionState::ACTIVE) {
        std::cout << "Skipping keepalive response - client " << session->getClientId() 
                  << " not in ACTIVE state (current: " << static_cast<int>(session->getState()) << ")" << std::endl;
        return;
    }
    
    auto response = session->createSecureMessage(common::MessageType::KEEPALIVE);
    if (response) {
        // 为心跳响应设置空载荷
        const std::string keepalive_data = "PONG";
        response->setPayload(reinterpret_cast<const uint8_t*>(keepalive_data.c_str()), 
                           keepalive_data.length());
        
        if (!sendSecureMessage(session, std::move(response))) {
            std::cout << "Failed to send keepalive response to client " << session->getClientId() << std::endl;
        } else {
            std::cout << "Keepalive response sent to client " << session->getClientId() << std::endl;
        }
    } else {
        std::cout << "Failed to create keepalive response for client " << session->getClientId() 
                  << " (secure_context is null)" << std::endl;
    }
}

void VPNServer::handleDisconnect(SessionPtr session, const common::SecureMessage* message) {
    if (!session || !message) {
        return;
    }
    
    std::cout << "Client " << session->getClientId() << " requested disconnect" << std::endl;
    
    session->setState(SessionState::DISCONNECTING);
    
    // 发送断开连接确认
    auto response = session->createSecureMessage(common::MessageType::DISCONNECT);
    if (response) {
        sendSecureMessage(session, std::move(response));
    }
    
    // 标记为断开连接
    session->setState(SessionState::DISCONNECTED);
    
    // 立即清理断开的会话，避免延迟
    std::cout << "Immediately cleaning up disconnected session " << session->getClientId() << std::endl;
    removeSession(session->getClientId());
}

bool VPNServer::sendSecureMessage(SessionPtr session, std::unique_ptr<common::SecureMessage> message) {
    if (!session || !message) {
        std::cerr << "sendSecureMessage: Invalid session or message" << std::endl;
        return false;
    }
    
    // 如果需要加密且握手已完成
    bool should_encrypt = (message->getType() != common::MessageType::HANDSHAKE_INIT &&
                          message->getType() != common::MessageType::HANDSHAKE_RESPONSE &&
                          session->isHandshakeComplete());
    
    // 只在非心跳包加密时输出调试信息
    if (should_encrypt && message->getType() != common::MessageType::KEEPALIVE) {
        std::cout << "Encrypting message type " << static_cast<int>(message->getType()) 
                  << " for client " << session->getClientId() << std::endl;
    }
    
    if (should_encrypt) {
        if (!session->encryptMessage(*message)) {
            std::cerr << "ENCRYPTION FAILED for client " << session->getClientId() 
                      << ", message type: " << static_cast<int>(message->getType()) 
                      << ", handshake_complete: " << (session->isHandshakeComplete() ? "yes" : "no")
                      << ", session_state: " << static_cast<int>(session->getState()) << std::endl;
            
            // 加密失败，但不要重新初始化，因为这会破坏已建立的连接
            // 对于已建立连接的会话，加密失败可能是临时问题
            std::cerr << "Skipping message due to encryption failure for client " << session->getClientId() << std::endl;
            return false;
        }
    }
    
    // 序列化消息
    uint8_t buffer[common::MAX_PACKET_SIZE];
    size_t actual_size;
    
    if (!message->serialize(buffer, sizeof(buffer), &actual_size)) {
        std::cerr << "Failed to serialize message" << std::endl;
        return false;
    }
    
    // 发送UDP数据包
    const struct sockaddr_in& client_addr = session->getEndpoint();
    int bytes_sent = sendto(udp_socket_, 
                           reinterpret_cast<const char*>(buffer), 
                           static_cast<int>(actual_size), 0,
                           reinterpret_cast<const struct sockaddr*>(&client_addr),
                           sizeof(client_addr));
    
    if (bytes_sent > 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_sent += bytes_sent;
        stats_.packets_sent++;
        
        session->updateSendStats(bytes_sent);
        
        // 只记录非心跳包的发送消息
        if (message->getType() != common::MessageType::KEEPALIVE) {
            std::cout << "Sent message to client " << session->getClientId() 
                      << ", type: " << static_cast<int>(message->getType())
                      << ", bytes: " << bytes_sent << std::endl;
        }
        return true;
    } else {
        std::cerr << "Failed to send UDP packet to client " << session->getClientId() 
                  << ", error: " << strerror(errno) << " (bytes_sent: " << bytes_sent << ")" << std::endl;
        return false;
    }
    
    return false;
}

void VPNServer::forwardPacketToClient(SessionPtr target_session, const uint8_t* data, size_t length) {
    if (!target_session || !data || length == 0) {
        return;
    }
    
    // 创建数据包消息
    auto message = target_session->createSecureMessage(common::MessageType::DATA_PACKET);
    if (!message) {
        return;
    }
    
    message->setPayload(data, length);
    sendSecureMessage(target_session, std::move(message));
}

void VPNServer::broadcastEncryptedPacket(const uint8_t* data, size_t length, ClientId exclude_client) {
    if (!data || length == 0) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (const auto& pair : sessions_) {
        if (pair.first != exclude_client && pair.second->getState() == SessionState::ACTIVE) {
            forwardPacketToClient(pair.second, data, length);
        }
    }
}

void VPNServer::handleTunPacket(const uint8_t* data, size_t length) {
    std::cout << "handleTunPacket called with " << length << " bytes" << std::endl;
    
    if (!packet_router_) {
        std::cout << "No packet router available" << std::endl;
        return;
    }
    
    // Use router to process packets from TUN interface
    auto routing_result = packet_router_->routePacket(data, length);
    
    std::cout << "Routing result: action=" << static_cast<int>(routing_result.action) 
              << ", reason=" << routing_result.reason << std::endl;
    
    switch (routing_result.action) {
        case PacketRouter::RoutingResult::TO_CLIENT:
            if (routing_result.target_session) {
                std::cout << "Forwarding packet to client " << routing_result.target_client << std::endl;
                // Send to specific client - forward encrypted packet
                forwardPacketToClient(routing_result.target_session, data, length);
            } else {
                std::cout << "No target session found for client " << routing_result.target_client << std::endl;
            }
            break;
            
        case PacketRouter::RoutingResult::BROADCAST:
            std::cout << "Broadcasting packet to all clients" << std::endl;
            // Broadcast to all clients
            broadcastEncryptedPacket(data, length);
            break;
            
        case PacketRouter::RoutingResult::DROP:
        default:
            std::cout << "Dropping packet: " << routing_result.reason << std::endl;
            break;
    }
}

SessionPtr VPNServer::findOrCreateSession(const struct sockaddr_in& client_addr) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // Find existing session by client address
    std::string client_key = std::string(inet_ntoa(client_addr.sin_addr)) + ":" + 
                            std::to_string(ntohs(client_addr.sin_port));
    
    // 首先检查是否有相同IP地址的现有会话（忽略端口，因为客户端重连时端口可能变化）
    for (auto& pair : sessions_) {
        const struct sockaddr_in& existing_addr = pair.second->getEndpoint();
        if (existing_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr) {
            auto current_state = pair.second->getState();
            
            // 如果会话在正常的连接过程中，只更新端点和活跃时间
            if (current_state == SessionState::ACTIVE || 
                current_state == SessionState::AUTHENTICATED ||
                current_state == SessionState::CONNECTING ||
                current_state == SessionState::HANDSHAKING ||
                current_state == SessionState::AUTHENTICATING) {
                
                pair.second->setEndpoint(client_addr);
                pair.second->updateLastActivity();
                
                // 减少日志输出，只在状态变化时记录
                if (existing_addr.sin_port != client_addr.sin_port) {
                    std::cout << "Updated endpoint for session " << pair.first 
                              << ", new port: " << ntohs(client_addr.sin_port) << std::endl;
                }
                return pair.second;
            }
            
            // 只有在会话真正处于错误状态时才删除
            if (current_state == SessionState::DISCONNECTED || 
                current_state == SessionState::DISCONNECTING) {
                
                std::cout << "Found disconnected session for client IP: " << inet_ntoa(client_addr.sin_addr) 
                          << " (ID: " << pair.first << ", state: " << static_cast<int>(current_state) 
                          << "), removing and creating new session" << std::endl;
                
                // 移除旧会话
                removeSession(pair.first);
                break; // 退出循环，创建新会话
            }
            
            // 其他情况直接返回现有会话
            std::cout << "Reusing existing session for client IP: " << inet_ntoa(client_addr.sin_addr) 
                      << " (ID: " << pair.first << ", state: " << static_cast<int>(current_state) << ")" << std::endl;
            return pair.second;
        }
    }
    
    // Check if maximum client limit is reached
    if (sessions_.size() >= config_->getMaxClients()) {
        std::cerr << "Maximum client limit reached: " << config_->getMaxClients() << std::endl;
        return nullptr;
    }
    
    // 生成新的唯一客户端ID（避免重复）
    ClientId client_id;
    do {
        client_id = next_client_id_++;
        if (next_client_id_ > 999999) {
            next_client_id_ = 1; // 循环使用ID
        }
    } while (sessions_.find(client_id) != sessions_.end());
    
    // Create new session
    SessionPtr session = std::make_shared<ClientSession>(client_id);
    session->setEndpoint(client_addr);
    session->setState(SessionState::CONNECTING);
    
    sessions_[client_id] = session;
    
    std::cout << "New client connected: " << client_key << " (ID: " << client_id << ")" << std::endl;
    
    return session;
}

void VPNServer::removeSession(ClientId client_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // 检查服务器是否正在停止
    if (should_stop_.load()) {
        std::cout << "Server is stopping, skipping session removal for client: " << client_id << std::endl;
        return;
    }
    
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        const std::string& virtual_ip = it->second->getVirtualIP();
        SessionState state = it->second->getState();
        
        // Remove client route from router
        if (packet_router_) {
            try {
                packet_router_->removeClientRoute(client_id);
            } catch (const std::exception& e) {
                std::cerr << "Error removing client route: " << e.what() << std::endl;
            }
        }
        
        // Remove from IP mapping and release IP
        if (!virtual_ip.empty()) {
            ip_to_client_.erase(virtual_ip);
            
            // 检查是否有其他会话正在使用相同的IP（重用会话的情况）
            bool ip_still_in_use = false;
            for (const auto& other_pair : sessions_) {
                if (other_pair.first != client_id && other_pair.second->getVirtualIP() == virtual_ip) {
                    ip_still_in_use = true;
                    std::cout << "IP " << virtual_ip << " is still in use by session " << other_pair.first << std::endl;
                    break;
                }
            }
            
            if (!ip_still_in_use) {
                try {
                    releaseVirtualIP(virtual_ip);
                } catch (const std::exception& e) {
                    std::cerr << "Error releasing IP " << virtual_ip << ": " << e.what() << std::endl;
                }
            }
        }
        
        sessions_.erase(it);
        
        std::cout << "Client session removed: ID " << client_id 
                  << ", IP " << virtual_ip 
                  << ", State " << static_cast<int>(state) 
                  << ", Remaining clients: " << sessions_.size() << std::endl;
    } else {
        std::cout << "Warning: Attempted to remove non-existent client session: ID " << client_id << std::endl;
    }
}

void VPNServer::cleanupInactiveSessions() {
    // 检查服务器是否正在停止
    if (should_stop_.load()) {
        return;
    }
    
    std::vector<ClientId> expired_clients;
    std::vector<ClientId> disconnected_clients;
    std::vector<ClientId> connecting_timeout_clients;
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        for (const auto& pair : sessions_) {
            try {
                SessionState state = pair.second->getState();
                
                // 清理超时的会话（基于心跳包检测）
                // 对于已连接的客户端，使用合理的超时时间（心跳包间隔的10倍）
                int timeout_seconds = config_->getClientTimeoutSeconds();
                if (state == SessionState::ACTIVE) {
                    // 活跃客户端的心跳包间隔是1秒，使用30秒超时（允许网络波动和连接问题）
                    timeout_seconds = 30;
                } else if (state == SessionState::AUTHENTICATED) {
                    // 已认证但未完全激活的客户端，使用较短超时
                    timeout_seconds = 15;
                }
                
                if (pair.second->isExpired(timeout_seconds)) {
                    // 计算实际的非活跃时间
                    auto now = std::chrono::steady_clock::now();
                    auto last_activity = pair.second->getStats().last_activity;
                    auto inactive_duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity);
                    
                    expired_clients.push_back(pair.first);
                    std::cout << "Session " << pair.first << " expired (state: " << static_cast<int>(state) 
                              << ", timeout: " << timeout_seconds << "s"
                              << ", inactive_for: " << inactive_duration.count() << "s)" << std::endl;
                }
                // 立即清理已断开连接的会话
                else if (state == SessionState::DISCONNECTED) {
                    disconnected_clients.push_back(pair.first);
                    std::cout << "Session " << pair.first << " marked as disconnected, cleaning up" << std::endl;
                }
                // 清理长时间处于连接状态的会话（超过10秒）
                else if (state == SessionState::CONNECTING && 
                         pair.second->isExpired(10)) {
                    connecting_timeout_clients.push_back(pair.first);
                    std::cout << "Session " << pair.first << " stuck in connecting state, cleaning up" << std::endl;
                }
                // 清理长时间处于握手状态的会话（超过15秒）
                else if (state == SessionState::HANDSHAKING && 
                         pair.second->isExpired(15)) {
                    connecting_timeout_clients.push_back(pair.first);
                    std::cout << "Session " << pair.first << " stuck in handshaking state, cleaning up" << std::endl;
                }
                // 清理长时间处于认证状态的会话（超过15秒）
                else if (state == SessionState::AUTHENTICATING && 
                         pair.second->isExpired(15)) {
                    connecting_timeout_clients.push_back(pair.first);
                    std::cout << "Session " << pair.first << " stuck in authenticating state, cleaning up" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error checking session " << pair.first << ": " << e.what() << std::endl;
            }
        }
    }
    
    // Clean up expired sessions
    for (ClientId client_id : expired_clients) {
        try {
            removeSession(client_id);
        } catch (const std::exception& e) {
            std::cerr << "Error removing expired session " << client_id << ": " << e.what() << std::endl;
        }
    }
    
    // Clean up disconnected sessions
    for (ClientId client_id : disconnected_clients) {
        try {
            removeSession(client_id);
        } catch (const std::exception& e) {
            std::cerr << "Error removing disconnected session " << client_id << ": " << e.what() << std::endl;
        }
    }
    
    // Clean up connecting timeout sessions
    for (ClientId client_id : connecting_timeout_clients) {
        try {
            removeSession(client_id);
        } catch (const std::exception& e) {
            std::cerr << "Error removing connecting timeout session " << client_id << ": " << e.what() << std::endl;
        }
    }
    
    if (!expired_clients.empty() || !disconnected_clients.empty() || !connecting_timeout_clients.empty()) {
        std::cout << "Session cleanup: " << expired_clients.size() << " expired, " 
                  << disconnected_clients.size() << " disconnected, "
                  << connecting_timeout_clients.size() << " timeout sessions" << std::endl;
    }
    
    // 清理过期的延迟释放IP
    cleanupDelayedReleaseIPs();
    
    // 定期输出会话状态统计（每10次清理输出一次）
    static int cleanup_count = 0;
    cleanup_count++;
    if (cleanup_count % 10 == 0) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        std::cout << "Session status check: " << sessions_.size() << " total sessions" << std::endl;
        for (const auto& pair : sessions_) {
            SessionState state = pair.second->getState();
            std::cout << "  Session " << pair.first << ": state=" << static_cast<int>(state) 
                      << ", IP=" << pair.second->getVirtualIP() << std::endl;
        }
        
        // 输出IP地址池状态
        printIPPoolStatus();
    }
}

void VPNServer::routePacketToClient(const uint8_t* data, size_t length, 
                                   const std::string& dest_ip) {
    ClientId client_id = packet_router_->findClientByIP(dest_ip);
    if (client_id == 0) {
        return;
    }
    
    SessionPtr session = packet_router_->getClientSession(client_id);
    if (!session) {
        return;
    }
    
    // Need to implement encryption and UDP sending logic here
    // For simplified implementation, send raw data directly
    const struct sockaddr_in& client_addr = session->getEndpoint();
    
    int bytes_sent = sendto(udp_socket_, 
                           reinterpret_cast<const char*>(data), 
                           static_cast<int>(length), 0,
                           reinterpret_cast<const struct sockaddr*>(&client_addr),
                           sizeof(client_addr));
    
    if (bytes_sent > 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_sent += bytes_sent;
        stats_.packets_sent++;
        
        session->updateSendStats(bytes_sent);
    }
}

void VPNServer::broadcastPacket(const uint8_t* data, size_t length, ClientId exclude_client) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    for (const auto& pair : sessions_) {
        if (pair.first == exclude_client) {
            continue;
        }
        
        SessionPtr session = pair.second;
        if (session->getState() != SessionState::ACTIVE) {
            continue;
        }
        
        // 发送给客户端
        const struct sockaddr_in& client_addr = session->getEndpoint();
        
        int bytes_sent = sendto(udp_socket_, 
                               reinterpret_cast<const char*>(data), 
                               static_cast<int>(length), 0,
                               reinterpret_cast<const struct sockaddr*>(&client_addr),
                               sizeof(client_addr));
        
        if (bytes_sent > 0) {
            session->updateSendStats(bytes_sent);
        }
    }
    
    // 更新统计信息
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.bytes_sent += length * (sessions_.size() - (exclude_client != 0 ? 1 : 0));
    stats_.packets_sent += (sessions_.size() - (exclude_client != 0 ? 1 : 0));
}

void VPNServer::closeSocket() {
    if (udp_socket_ >= 0) {
#ifdef _WIN32
        closesocket(udp_socket_);
#else
        close(udp_socket_);
#endif
        udp_socket_ = -1;
    }
}

bool VPNServer::initializeIPPool() {
    if (!config_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    // 解析基础网络地址
    std::string network = config_->getVirtualNetwork();
    std::string netmask = config_->getVirtualNetmask();
    
    struct in_addr addr;
    if (inet_aton(network.c_str(), &addr) == 0) {
        std::cerr << "Invalid virtual network: " << network << std::endl;
        return false;
    }
    base_ip_ = ntohl(addr.s_addr);
    
    if (inet_aton(netmask.c_str(), &addr) == 0) {
        std::cerr << "Invalid netmask: " << netmask << std::endl;
        return false;
    }
    netmask_ = ntohl(addr.s_addr);
    
    // 清空已分配IP列表
    allocated_ips_.clear();
    next_ip_offset_ = 2; // 从.2开始分配（.1通常是网关）
    
    std::cout << "IP pool initialized: " << network << "/" << netmask 
              << ", starting from offset " << next_ip_offset_ << std::endl;
    
    return true;
}

std::string VPNServer::allocateVirtualIP() {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    // 计算网络中可用的主机数量
    uint32_t host_mask = ~netmask_;
    uint32_t max_hosts = host_mask - 1; // 减去广播地址
    
    // 优先查找已释放的IP地址（从头开始搜索，优先使用小的IP）
    for (uint32_t offset = 2; offset <= max_hosts; ++offset) {
        uint32_t ip_uint = base_ip_ + offset;
        
        // 检查这个IP是否已被分配
        if (allocated_ips_.find(ip_uint) == allocated_ips_.end()) {
            // 检查是否在延迟释放列表中
            auto delayed_it = delayed_release_ips_.find(ip_uint);
            if (delayed_it != delayed_release_ips_.end()) {
                // 检查延迟时间是否已过
                auto now = std::chrono::steady_clock::now();
                if (now - delayed_it->second < std::chrono::seconds(30)) {
                    // 还在延迟期内，跳过这个IP
                    continue;
                } else {
                    // 延迟期已过，可以重新分配
                    delayed_release_ips_.erase(delayed_it);
                }
            }
            
            // 分配这个IP
            allocated_ips_.insert(ip_uint);
            
            // 更新next_ip_offset_为当前分配IP的下一个位置
            // 这样下次分配时会继续从这个位置开始，但优先使用已释放的小IP
            if (offset >= next_ip_offset_) {
                next_ip_offset_ = offset + 1;
            }
            
            // 转换为字符串
            struct in_addr addr;
            addr.s_addr = htonl(ip_uint);
            std::string ip_str = inet_ntoa(addr);
            
            // 更新IP到客户端的映射（这里需要客户端ID，但当前函数没有这个参数）
            // 这个映射会在assignVirtualIP中更新
            
            std::cout << "Allocated virtual IP: " << ip_str << " (offset: " << offset 
                      << ", next_offset: " << next_ip_offset_ << ")" << std::endl;
            return ip_str;
        }
    }
    
    std::cerr << "No available virtual IP addresses in pool" << std::endl;
    return ""; // 没有可用IP
}

void VPNServer::releaseVirtualIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 0) {
        std::cerr << "Invalid IP address to release: " << ip << std::endl;
        return;
    }
    
    uint32_t ip_uint = ntohl(addr.s_addr);
    uint32_t offset = ip_uint - base_ip_;
    
    auto it = allocated_ips_.find(ip_uint);
    if (it != allocated_ips_.end()) {
        allocated_ips_.erase(it);
        
        // 添加到延迟释放列表，30秒后才能重新分配
        delayed_release_ips_[ip_uint] = std::chrono::steady_clock::now();
        
        std::cout << "Released virtual IP: " << ip << " (offset: " << offset 
                  << ", pool size: " << allocated_ips_.size() 
                  << ", delayed for 30s)" << std::endl;
    } else {
        std::cout << "Warning: Attempted to release unallocated IP: " << ip << std::endl;
    }
}

void VPNServer::cleanupDelayedReleaseIPs() {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = delayed_release_ips_.begin();
    
    while (it != delayed_release_ips_.end()) {
        if (now - it->second >= std::chrono::seconds(30)) {
            // 延迟期已过，可以从延迟列表中移除
            struct in_addr addr;
            addr.s_addr = htonl(it->first);
            std::cout << "IP " << inet_ntoa(addr) << " delay period expired, available for reallocation" << std::endl;
            it = delayed_release_ips_.erase(it);
        } else {
            ++it;
        }
    }
}

void VPNServer::printIPPoolStatus() {
    std::lock_guard<std::mutex> lock(ip_pool_mutex_);
    
    std::cout << "IP Pool Status:" << std::endl;
    std::cout << "  Next offset: " << next_ip_offset_ << std::endl;
    std::cout << "  Allocated IPs: " << allocated_ips_.size() << std::endl;
    std::cout << "  Delayed release IPs: " << delayed_release_ips_.size() << std::endl;
    
    if (!allocated_ips_.empty()) {
        std::cout << "  Allocated IP list: ";
        for (uint32_t ip_uint : allocated_ips_) {
            struct in_addr addr;
            addr.s_addr = htonl(ip_uint);
            std::cout << inet_ntoa(addr) << " ";
        }
        std::cout << std::endl;
    }
    
    if (!delayed_release_ips_.empty()) {
        std::cout << "  Delayed release IP list: ";
        for (const auto& pair : delayed_release_ips_) {
            struct in_addr addr;
            addr.s_addr = htonl(pair.first);
            std::cout << inet_ntoa(addr) << " ";
        }
        std::cout << std::endl;
    }
}

} // namespace server
} // namespace sduvpn
