#pragma once

#include <memory>
#include <unordered_map>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "common/secure_protocol.h"

namespace sduvpn {
namespace server {

// 前向声明
class ClientSession;
class TunTapInterface;
class ServerConfig;
class PacketRouter;

using ClientId = uint32_t;
using SessionPtr = std::shared_ptr<ClientSession>;

/**
 * @brief VPN服务器核心类
 * 
 * 负责管理客户端连接、数据包路由和转发
 */
class VPNServer {
public:
    VPNServer();
    ~VPNServer();

    // 禁用拷贝构造和赋值
    VPNServer(const VPNServer&) = delete;
    VPNServer& operator=(const VPNServer&) = delete;

    /**
     * @brief 启动服务器
     * @param config 服务器配置
     * @return 是否启动成功
     */
    bool start(const ServerConfig& config);

    /**
     * @brief 停止服务器
     */
    void stop();

    /**
     * @brief 获取运行状态
     * @return 是否正在运行
     */
    bool isRunning() const { return running_.load(); }

    /**
     * @brief 获取连接的客户端数量
     * @return 客户端数量
     */
    size_t getClientCount() const;

    /**
     * @brief 获取服务器统计信息
     */
    struct Statistics {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint32_t active_clients = 0;
        uint64_t uptime_seconds = 0;
    };

    Statistics getStatistics() const;

private:
    // 网络处理
    void networkThreadFunc();
    void handleClientMessage(const struct sockaddr_in& client_addr, 
                           const uint8_t* data, size_t length);
    
    // 安全消息处理
    void handleHandshakeInit(SessionPtr session, const common::SecureMessage* message);
    void handleHandshakeComplete(SessionPtr session, const common::SecureMessage* message);
    void handleAuthRequest(SessionPtr session, const common::SecureMessage* message);
    void handleDataPacket(SessionPtr session, const common::SecureMessage* message);
    void handleKeepAlive(SessionPtr session, const common::SecureMessage* message);
    void handleDisconnect(SessionPtr session, const common::SecureMessage* message);
    
    // 消息发送
    bool sendSecureMessage(SessionPtr session, std::unique_ptr<common::SecureMessage> message);
    void forwardPacketToClient(SessionPtr target_session, const uint8_t* data, size_t length);
    void broadcastEncryptedPacket(const uint8_t* data, size_t length, ClientId exclude_client = 0);
    
    // TUN接口处理
    void tunThreadFunc();
    void handleTunPacket(const uint8_t* data, size_t length);
    
    // 客户端管理
    SessionPtr findOrCreateSession(const struct sockaddr_in& client_addr);
    void removeSession(ClientId client_id);
    void cleanupInactiveSessions();
    
    // 数据包路由
    void routePacketToClient(const uint8_t* data, size_t length, 
                           const std::string& dest_ip);
    void broadcastPacket(const uint8_t* data, size_t length, 
                        ClientId exclude_client = 0);

private:
    // 运行状态
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};
    
    // 网络相关
    int udp_socket_{-1};
    uint16_t listen_port_{0};
    std::thread network_thread_;
    
    // TUN接口
    std::unique_ptr<TunTapInterface> tun_interface_;
    std::thread tun_thread_;
    
    // 客户端会话管理
    mutable std::mutex sessions_mutex_;
    std::unordered_map<ClientId, SessionPtr> sessions_;
    std::unordered_map<std::string, ClientId> ip_to_client_; // 虚拟IP到客户端ID映射
    ClientId next_client_id_{1};
    
    // 路由管理
    std::unique_ptr<PacketRouter> packet_router_;
    
    // 配置
    std::unique_ptr<ServerConfig> config_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    Statistics stats_;
    std::chrono::steady_clock::time_point start_time_;
    
    // 清理定时器
    std::thread cleanup_thread_;
    void cleanupThreadFunc();
    
    // 辅助方法
    void closeSocket();
};

} // namespace server
} // namespace sduvpn
