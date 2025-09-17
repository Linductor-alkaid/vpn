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
        std::cerr << "服务器已经在运行" << std::endl;
        return false;
    }
    
    // 验证配置
    if (!config.validate()) {
        std::cerr << "服务器配置无效" << std::endl;
        return false;
    }
    
    // 保存配置
    config_ = std::make_unique<ServerConfig>(config);
    listen_port_ = config.getListenPort();
    
    std::cout << "启动SDUVPN服务器..." << std::endl;
    std::cout << "监听端口: " << listen_port_ << std::endl;
    std::cout << "虚拟网络: " << config.getVirtualNetwork() << "/" << config.getVirtualNetmask() << std::endl;
    std::cout << "最大客户端: " << config.getMaxClients() << std::endl;
    
    // 创建UDP套接字
    udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_ < 0) {
        std::cerr << "创建UDP套接字失败" << std::endl;
        return false;
    }
    
    // 设置套接字选项
    int reuse = 1;
    if (setsockopt(udp_socket_, SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&reuse), sizeof(reuse)) < 0) {
        std::cerr << "设置SO_REUSEADDR失败" << std::endl;
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
            std::cerr << "无效的绑定地址: " << config.getBindAddress() << std::endl;
            closeSocket();
            return false;
        }
    }
    
    if (bind(udp_socket_, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
#ifdef _WIN32
        std::cerr << "绑定地址失败: " << WSAGetLastError() << std::endl;
#else
        std::cerr << "绑定地址失败: " << strerror(errno) << std::endl;
#endif
        closeSocket();
        return false;
    }
    
    // 创建TUN接口
    tun_interface_ = std::make_unique<TunTapInterface>();
    if (!tun_interface_->createTun(config.getTunInterfaceName())) {
        std::cerr << "创建TUN接口失败" << std::endl;
        closeSocket();
        return false;
    }
    
    // 配置TUN接口
    if (!tun_interface_->setIPAddress(config.getVirtualNetwork(), config.getVirtualNetmask())) {
        std::cerr << "设置TUN接口IP地址失败" << std::endl;
        closeSocket();
        return false;
    }
    
    if (!tun_interface_->bringUp()) {
        std::cerr << "启用TUN接口失败" << std::endl;
        closeSocket();
        return false;
    }
    
    // 设置TUN接口为非阻塞模式
    tun_interface_->setNonBlocking(true);
    
    // 初始化数据包路由器
    packet_router_ = std::make_unique<PacketRouter>();
    if (!packet_router_->initialize(config.getVirtualNetwork(), config.getVirtualNetmask())) {
        std::cerr << "初始化数据包路由器失败" << std::endl;
        closeSocket();
        return false;
    }
    
    packet_router_->setDebugMode(config.isDebugMode());
    
    // 设置运行标志
    running_.store(true);
    should_stop_.store(false);
    
    // 启动工作线程
    network_thread_ = std::thread(&VPNServer::networkThreadFunc, this);
    tun_thread_ = std::thread(&VPNServer::tunThreadFunc, this);
    cleanup_thread_ = std::thread(&VPNServer::cleanupThreadFunc, this);
    
    std::cout << "SDUVPN服务器启动成功" << std::endl;
    return true;
}

void VPNServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "停止SDUVPN服务器..." << std::endl;
    
    // 设置停止标志
    should_stop_.store(true);
    running_.store(false);
    
    // 等待线程结束
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    // 关闭网络套接字
    closeSocket();
    
    // 关闭TUN接口
    if (tun_interface_) {
        tun_interface_->close();
        tun_interface_.reset();
    }
    
    // 清理客户端会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
        ip_to_client_.clear();
    }
    
    // 清理路由器
    packet_router_.reset();
    config_.reset();
    
    std::cout << "SDUVPN服务器已停止" << std::endl;
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
    std::cout << "网络线程启动" << std::endl;
    
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
                    std::cerr << "接收数据失败: " << error << std::endl;
                }
                break;
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                if (!should_stop_.load()) {
                    std::cerr << "接收数据失败: " << strerror(errno) << std::endl;
                }
                break;
            }
#endif
        }
        
        // 避免CPU占用过高
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    std::cout << "网络线程结束" << std::endl;
}

void VPNServer::tunThreadFunc() {
    std::cout << "TUN线程启动" << std::endl;
    
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
            // 非阻塞模式下的正常情况
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    std::cout << "TUN线程结束" << std::endl;
}

void VPNServer::cleanupThreadFunc() {
    std::cout << "清理线程启动" << std::endl;
    
    while (!should_stop_.load()) {
        cleanupInactiveSessions();
        
        // 每30秒清理一次
        for (int i = 0; i < 30 && !should_stop_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    std::cout << "清理线程结束" << std::endl;
}

void VPNServer::handleClientMessage(const struct sockaddr_in& client_addr, 
                                   const uint8_t* data, size_t length) {
    // 查找或创建客户端会话
    SessionPtr session = findOrCreateSession(client_addr);
    if (!session) {
        return;
    }
    
    // 更新会话活跃时间
    session->updateLastActivity();
    
    // 这里应该实现具体的消息处理逻辑
    // 包括认证、密钥交换、数据包解密等
    
    // 目前为简化实现，直接将数据作为IP数据包处理
    if (session->getState() == SessionState::ACTIVE) {
        // 使用路由器处理数据包
        auto routing_result = packet_router_->routePacket(data, length);
        
        switch (routing_result.action) {
            case PacketRouter::RoutingResult::TO_CLIENT:
                if (routing_result.target_session) {
                    // 转发给目标客户端
                    // 这里需要实现加密和发送逻辑
                }
                break;
                
            case PacketRouter::RoutingResult::TO_TUN:
                // 写入TUN接口
                if (tun_interface_) {
                    tun_interface_->writePacket(data, length);
                }
                break;
                
            case PacketRouter::RoutingResult::BROADCAST:
                // 广播给所有客户端
                broadcastPacket(data, length, session->getClientId());
                break;
                
            case PacketRouter::RoutingResult::DROP:
            default:
                // 丢弃数据包
                break;
        }
    }
}

void VPNServer::handleTunPacket(const uint8_t* data, size_t length) {
    if (!packet_router_) {
        return;
    }
    
    // 使用路由器处理TUN接口的数据包
    auto routing_result = packet_router_->routePacket(data, length);
    
    switch (routing_result.action) {
        case PacketRouter::RoutingResult::TO_CLIENT:
            if (routing_result.target_session) {
                // 发送给特定客户端
                // 这里需要实现加密和UDP发送逻辑
            }
            break;
            
        case PacketRouter::RoutingResult::BROADCAST:
            // 广播给所有客户端
            broadcastPacket(data, length);
            break;
            
        case PacketRouter::RoutingResult::DROP:
        default:
            // 丢弃数据包
            break;
    }
}

SessionPtr VPNServer::findOrCreateSession(const struct sockaddr_in& client_addr) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    // 根据客户端地址查找现有会话
    std::string client_key = std::string(inet_ntoa(client_addr.sin_addr)) + ":" + 
                            std::to_string(ntohs(client_addr.sin_port));
    
    // 简化实现：使用地址作为客户端ID的哈希
    ClientId client_id = std::hash<std::string>{}(client_key) % 1000000 + 1;
    
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        // 更新端点信息
        it->second->setEndpoint(client_addr);
        return it->second;
    }
    
    // 检查是否超过最大客户端数
    if (sessions_.size() >= config_->getMaxClients()) {
        std::cerr << "达到最大客户端数限制: " << config_->getMaxClients() << std::endl;
        return nullptr;
    }
    
    // 创建新会话
    SessionPtr session = std::make_shared<ClientSession>(client_id);
    session->setEndpoint(client_addr);
    session->setState(SessionState::CONNECTING);
    
    sessions_[client_id] = session;
    
    std::cout << "新客户端连接: " << client_key << " (ID: " << client_id << ")" << std::endl;
    
    return session;
}

void VPNServer::removeSession(ClientId client_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
        const std::string& virtual_ip = it->second->getVirtualIP();
        
        // 从路由器中删除客户端路由
        if (packet_router_) {
            packet_router_->removeClientRoute(client_id);
        }
        
        // 从IP映射中删除
        if (!virtual_ip.empty()) {
            ip_to_client_.erase(virtual_ip);
        }
        
        sessions_.erase(it);
        
        std::cout << "客户端断开: ID " << client_id << std::endl;
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
    
    // 清理过期会话
    for (ClientId client_id : expired_clients) {
        removeSession(client_id);
    }
    
    if (!expired_clients.empty()) {
        std::cout << "清理了 " << expired_clients.size() << " 个过期会话" << std::endl;
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
    
    // 这里需要实现加密和UDP发送逻辑
    // 目前为简化实现，直接发送原始数据
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
