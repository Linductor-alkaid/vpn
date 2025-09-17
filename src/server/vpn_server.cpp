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
    
    // Configure TUN interface
    if (!tun_interface_->setIPAddress(config.getVirtualNetwork(), config.getVirtualNetmask())) {
        std::cerr << "Failed to set TUN interface IP address" << std::endl;
        closeSocket();
        return false;
    }
    
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
    
    packet_router_->setDebugMode(config.isDebugMode());
    
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
        
        // Cleanup every 30 seconds
        for (int i = 0; i < 30 && !should_stop_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
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
    
    // This should implement specific message processing logic
    // including authentication, key exchange, packet decryption, etc.
    
    // For simplified implementation, directly process data as IP packets
    if (session->getState() == SessionState::ACTIVE) {
        // Use router to process packets
        auto routing_result = packet_router_->routePacket(data, length);
        
        switch (routing_result.action) {
            case PacketRouter::RoutingResult::TO_CLIENT:
                if (routing_result.target_session) {
                // Forward to target client
                // Need to implement encryption and sending logic here
                }
                break;
                
            case PacketRouter::RoutingResult::TO_TUN:
                // Write to TUN interface
                if (tun_interface_) {
                    tun_interface_->writePacket(data, length);
                }
                break;
                
            case PacketRouter::RoutingResult::BROADCAST:
                // Broadcast to all clients
                broadcastPacket(data, length, session->getClientId());
                break;
                
            case PacketRouter::RoutingResult::DROP:
            default:
                // Drop packet
                break;
        }
    }
}

void VPNServer::handleTunPacket(const uint8_t* data, size_t length) {
    if (!packet_router_) {
        return;
    }
    
    // Use router to process packets from TUN interface
    auto routing_result = packet_router_->routePacket(data, length);
    
    switch (routing_result.action) {
        case PacketRouter::RoutingResult::TO_CLIENT:
            if (routing_result.target_session) {
            // Send to specific client
            // Need to implement encryption and UDP sending logic here
            }
            break;
            
        case PacketRouter::RoutingResult::BROADCAST:
            // Broadcast to all clients
            broadcastPacket(data, length);
            break;
            
        case PacketRouter::RoutingResult::DROP:
        default:
            // Drop packet
            break;
    }
}

SessionPtr VPNServer::findOrCreateSession(const struct sockaddr_in& client_addr) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // Find existing session by client address
    std::string client_key = std::string(inet_ntoa(client_addr.sin_addr)) + ":" + 
                            std::to_string(ntohs(client_addr.sin_port));
    
    // Simplified implementation: use address as client ID hash
    ClientId client_id = std::hash<std::string>{}(client_key) % 1000000 + 1;
    
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        // Update endpoint information
        it->second->setEndpoint(client_addr);
        return it->second;
    }
    
    // Check if maximum client limit is reached
    if (sessions_.size() >= config_->getMaxClients()) {
        std::cerr << "Maximum client limit reached: " << config_->getMaxClients() << std::endl;
        return nullptr;
    }
    
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
    
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        const std::string& virtual_ip = it->second->getVirtualIP();
        
        // Remove client route from router
        if (packet_router_) {
            packet_router_->removeClientRoute(client_id);
        }
        
        // Remove from IP mapping
        if (!virtual_ip.empty()) {
            ip_to_client_.erase(virtual_ip);
        }
        
        sessions_.erase(it);
        
        std::cout << "Client disconnected: ID " << client_id << std::endl;
    }
}

void VPNServer::cleanupInactiveSessions() {
    std::vector<ClientId> expired_clients;
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        for (const auto& pair : sessions_) {
            if (pair.second->isExpired(config_->getClientTimeoutSeconds())) {
                expired_clients.push_back(pair.first);
            }
        }
    }
    
    // Clean up expired sessions
    for (ClientId client_id : expired_clients) {
        removeSession(client_id);
    }
    
    if (!expired_clients.empty()) {
        std::cout << "Cleaned up " << expired_clients.size() << " expired sessions" << std::endl;
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

} // namespace server
} // namespace sduvpn
