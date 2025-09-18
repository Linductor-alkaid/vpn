#pragma once

#include "windows_tap_interface.h"
#include "crypto/crypto.h"
#include "crypto/key_exchange.h"
#include "common/secure_protocol.h"
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <functional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace sduvpn {
namespace client {

/**
 * @brief Windows VPN客户端核心类
 */
class WindowsVPNClient {
public:
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKING,
        AUTHENTICATING,
        CONNECTED,
        DISCONNECTING,
        ERROR_STATE
    };

    /**
     * @brief 连接配置结构
     */
    struct ConnectionConfig {
        std::string server_address;
        uint16_t server_port = 1194;
        std::string username;
        std::string password;
        std::string client_certificate_path;
        std::string client_private_key_path;
        std::string ca_certificate_path;
        std::string tap_adapter_name;
        std::string virtual_ip;
        std::string virtual_netmask = "255.255.255.0";
        uint32_t keepalive_interval = 30; // 秒
        uint32_t connection_timeout = 10; // 秒
        bool auto_reconnect = true;
        uint32_t max_reconnect_attempts = 5;
    };

    /**
     * @brief 连接统计信息
     */
    struct ConnectionStats {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        std::chrono::steady_clock::time_point connection_start_time;
        uint32_t reconnect_count = 0;
        std::string last_error;
    };

public:
    WindowsVPNClient();
    ~WindowsVPNClient();

    // 禁用拷贝构造和赋值
    WindowsVPNClient(const WindowsVPNClient&) = delete;
    WindowsVPNClient& operator=(const WindowsVPNClient&) = delete;

    /**
     * @brief 连接到VPN服务器
     * @param config 连接配置
     * @return 是否成功启动连接过程
     */
    bool connect(const ConnectionConfig& config);

    /**
     * @brief 断开VPN连接
     */
    void disconnect();

    /**
     * @brief 获取连接状态
     * @return 当前连接状态
     */
    ConnectionState getConnectionState() const { return connection_state_.load(); }

    /**
     * @brief 获取连接统计信息
     * @return 统计信息
     */
    ConnectionStats getConnectionStats() const;

    /**
     * @brief 获取最后一次错误信息
     * @return 错误信息
     */
    std::string getLastError() const;

    /**
     * @brief 设置日志回调函数
     * @param callback 日志回调函数
     */
    void setLogCallback(std::function<void(const std::string&)> callback);

    /**
     * @brief 带宽测试结果
     */
    struct BandwidthTestResult {
        double upload_mbps = 0.0;
        double download_mbps = 0.0;
        double latency_ms = 0.0;
        bool success = false;
        std::string error_message;
    };

    /**
     * @brief 执行带宽测试
     * @param test_duration_seconds 测试持续时间（秒）
     * @param test_size_mb 测试数据大小（MB）
     * @return 测试结果
     */
    BandwidthTestResult performBandwidthTest(uint32_t test_duration_seconds = 10, uint32_t test_size_mb = 10);

private:
    // 连接管理
    void connectionThreadFunc();
    bool performHandshake();
    bool authenticateWithServer();
    bool setupTunnel();
    
    // 数据处理线程
    void tapReaderThreadFunc();
    void networkReaderThreadFunc();
    void networkWriterThreadFunc();
    
    // 数据包处理
    bool processTapPacket(const uint8_t* data, size_t length);
    bool processNetworkPacket(const uint8_t* data, size_t length);
    
    // 网络通信
    bool createSocket();
    void closeSocket();
    bool sendToServer(const uint8_t* data, size_t length);
    bool receiveFromServer(uint8_t* buffer, size_t buffer_size, size_t* received_length);
    
    // 安全通信
    bool sendSecureMessage(std::unique_ptr<common::SecureMessage> message);
    bool processSecureMessage(const uint8_t* buffer, size_t buffer_size, 
                             std::unique_ptr<common::SecureMessage>& message);
    
    // 保活机制
    void keepaliveThreadFunc();
    bool sendKeepalive();
    
    // 重连机制
    void reconnectThreadFunc();
    bool shouldReconnect();
    
    // 辅助方法
    void setState(ConnectionState new_state);
    void logMessage(const std::string& message);
    void updateStats(uint64_t bytes_sent, uint64_t bytes_received, 
                    uint64_t packets_sent, uint64_t packets_received);
    
    // 错误处理
    void setLastError(const std::string& error);

private:
    // 连接状态
    std::atomic<ConnectionState> connection_state_{ConnectionState::DISCONNECTED};
    std::atomic<bool> should_stop_{false};
    
    // 配置
    ConnectionConfig config_;
    
    // TAP接口
    std::unique_ptr<WindowsTapInterface> tap_interface_;
    
    // 网络套接字
    SOCKET udp_socket_{INVALID_SOCKET};
    struct sockaddr_in server_addr_{};
    
    // 安全协议上下文
    std::unique_ptr<common::SecureProtocolContext> secure_context_;
    
    // 工作线程
    std::thread connection_thread_;
    std::thread tap_reader_thread_;
    std::thread network_reader_thread_;
    std::thread network_writer_thread_;
    std::thread keepalive_thread_;
    std::thread reconnect_thread_;
    
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
    
    // 日志回调
    std::function<void(const std::string&)> log_callback_;
    std::mutex log_mutex_;
    
    // 网络缓冲区
    static constexpr size_t NETWORK_BUFFER_SIZE = 2048;
    static constexpr size_t TAP_BUFFER_SIZE = 2048;
};

/**
 * @brief Windows VPN客户端管理器
 * 
 * 用于管理客户端实例和系统集成
 */
class WindowsVPNClientManager {
public:
    /**
     * @brief 获取单例实例
     * @return 管理器实例
     */
    static WindowsVPNClientManager& getInstance();

    /**
     * @brief 创建VPN客户端实例
     * @return 客户端实例
     */
    std::unique_ptr<WindowsVPNClient> createClient();

    /**
     * @brief 检查系统要求
     * @return 检查结果和错误信息
     */
    std::pair<bool, std::string> checkSystemRequirements();

    /**
     * @brief 初始化Winsock
     * @return 是否成功
     */
    bool initializeWinsock();

    /**
     * @brief 清理Winsock
     */
    void cleanupWinsock();

    /**
     * @brief 检查管理员权限
     * @return 是否具有管理员权限
     */
    bool hasAdministratorPrivileges();

    /**
     * @brief 请求管理员权限
     * @return 是否成功获取权限
     */
    bool requestAdministratorPrivileges();

private:
    WindowsVPNClientManager() = default;
    ~WindowsVPNClientManager();

    bool winsock_initialized_ = false;
};

} // namespace client
} // namespace sduvpn
