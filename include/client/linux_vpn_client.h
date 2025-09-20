#pragma once

#include "common/web_server.h"
#include "common/secure_protocol.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <functional>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace sduvpn {
namespace client {

// 前向声明
class LinuxTunInterface;

/**
 * @brief Linux VPN客户端
 * 
 * 实现Linux平台的VPN客户端功能，使用TUN接口
 */
class LinuxVPNClient : public common::VPNClientInterface {
public:
    LinuxVPNClient();
    virtual ~LinuxVPNClient();

    // 禁用拷贝构造和赋值
    LinuxVPNClient(const LinuxVPNClient&) = delete;
    LinuxVPNClient& operator=(const LinuxVPNClient&) = delete;

    // VPNClientInterface实现
    bool connect(const ConnectionConfig& config) override;
    void disconnect() override;
    ConnectionState getConnectionState() const override { return connection_state_.load(); }
    ConnectionStats getConnectionStats() const override;
    std::string getLastError() const override;
    BandwidthTestResult performBandwidthTest(uint32_t test_duration_seconds = 10, uint32_t test_size_mb = 5) override;
    bool testInterface() override;

    /**
     * @brief 设置日志回调
     */
    void setLogCallback(std::function<void(const std::string&)> callback);

private:
    // 连接管理
    void connectionThreadFunc();
    bool performHandshake();
    bool authenticateWithServer();
    bool setupTunnel();
    
    // 数据处理线程
    void tunReaderThreadFunc();
    void networkReaderThreadFunc();
    void networkWriterThreadFunc();
    void keepaliveThreadFunc();
    
    // 数据包处理
    bool processTunPacket(const uint8_t* data, size_t length);
    bool processNetworkPacket(const uint8_t* data, size_t length);
    
    // 网络通信
    bool createSocket();
    void closeSocket();
    bool sendToServer(const uint8_t* data, size_t length);
    bool receiveFromServer(uint8_t* buffer, size_t buffer_size, size_t* received_length);
    
    // 安全消息处理
    bool sendSecureMessage(std::unique_ptr<common::SecureMessage> message);
    bool processSecureMessage(const uint8_t* buffer, size_t buffer_size,
                             std::unique_ptr<common::SecureMessage>& message);
    
    // 保活机制
    bool sendKeepalive();
    
    // 状态管理
    void setState(ConnectionState new_state);
    void logMessage(const std::string& message);
    void updateStats(uint64_t bytes_sent, uint64_t bytes_received, 
                    uint64_t packets_sent, uint64_t packets_received);
    void setLastError(const std::string& error);

private:
    // 配置
    ConnectionConfig config_;
    
    // 连接状态
    std::atomic<ConnectionState> connection_state_{ConnectionState::DISCONNECTED};
    std::atomic<bool> should_stop_{false};
    
    // 网络套接字
    int udp_socket_{-1};
    struct sockaddr_in server_addr_;
    
    // TUN接口
    std::unique_ptr<LinuxTunInterface> tun_interface_;
    
    // 安全协议上下文
    std::unique_ptr<common::SecureProtocolContext> secure_context_;
    
    // 线程管理
    std::thread connection_thread_;
    std::thread tun_reader_thread_;
    std::thread network_reader_thread_;
    std::thread network_writer_thread_;
    std::thread keepalive_thread_;
    
    // 数据队列
    std::queue<std::vector<uint8_t>> outbound_queue_;
    std::mutex outbound_queue_mutex_;
    std::condition_variable outbound_queue_cv_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    ConnectionStats stats_;
    
    // 错误信息
    mutable std::mutex error_mutex_;
    std::string last_error_;
    
    // 日志系统
    mutable std::mutex log_mutex_;
    std::function<void(const std::string&)> log_callback_;
    
    // 缓冲区大小
    static constexpr size_t TUN_BUFFER_SIZE = 2048;
    static constexpr size_t NETWORK_BUFFER_SIZE = 4096;
};

/**
 * @brief Linux VPN客户端管理器
 * 
 * 单例模式，管理VPN客户端实例的创建和系统要求检查
 */
class LinuxVPNClientManager {
public:
    static LinuxVPNClientManager& getInstance();
    
    // 禁用拷贝构造和赋值
    LinuxVPNClientManager(const LinuxVPNClientManager&) = delete;
    LinuxVPNClientManager& operator=(const LinuxVPNClientManager&) = delete;

    /**
     * @brief 创建VPN客户端实例
     */
    std::unique_ptr<LinuxVPNClient> createClient();

    /**
     * @brief 检查系统要求
     * @return {是否满足要求, 错误信息}
     */
    std::pair<bool, std::string> checkSystemRequirements();

private:
    LinuxVPNClientManager() = default;
    ~LinuxVPNClientManager() = default;
    
    bool hasRootPrivileges();
    bool isTunModuleAvailable();
};

} // namespace client
} // namespace sduvpn
