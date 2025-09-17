#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <atomic>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "crypto/crypto.h"

namespace sduvpn {
namespace server {

using ClientId = uint32_t;

/**
 * @brief 客户端会话状态
 */
enum class SessionState {
    CONNECTING,     // 正在连接
    AUTHENTICATING, // 正在认证
    AUTHENTICATED,  // 已认证
    ACTIVE,        // 活跃状态
    DISCONNECTING, // 正在断开
    DISCONNECTED   // 已断开
};

/**
 * @brief 客户端认证信息
 */
struct AuthInfo {
    std::string username;
    std::string client_version;
    std::string device_id;
    std::chrono::system_clock::time_point auth_time;
};

/**
 * @brief 客户端会话类
 * 
 * 管理单个客户端的连接状态、认证信息和加密上下文
 */
class ClientSession {
public:
    explicit ClientSession(ClientId client_id);
    ~ClientSession();

    // 禁用拷贝构造和赋值
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    /**
     * @brief 获取客户端ID
     */
    ClientId getClientId() const { return client_id_; }

    /**
     * @brief 设置客户端网络地址
     */
    void setEndpoint(const struct sockaddr_in& endpoint);

    /**
     * @brief 获取客户端网络地址
     */
    const struct sockaddr_in& getEndpoint() const { return endpoint_; }

    /**
     * @brief 获取会话状态
     */
    SessionState getState() const { return state_.load(); }

    /**
     * @brief 设置会话状态
     */
    void setState(SessionState state) { state_.store(state); }

    /**
     * @brief 分配虚拟IP地址
     * @param virtual_ip 虚拟IP地址字符串
     */
    void assignVirtualIP(const std::string& virtual_ip);

    /**
     * @brief 获取虚拟IP地址
     */
    const std::string& getVirtualIP() const { return virtual_ip_; }

    /**
     * @brief 处理认证请求
     * @param username 用户名
     * @param password 密码
     * @param client_info 客户端信息
     * @return 是否认证成功
     */
    bool authenticate(const std::string& username, 
                     const std::string& password,
                     const std::string& client_info);

    /**
     * @brief 获取认证信息
     */
    const AuthInfo& getAuthInfo() const { return auth_info_; }

    /**
     * @brief 初始化加密上下文
     * @param shared_key 共享密钥
     * @return 是否初始化成功
     */
    bool initializeCrypto(const std::vector<uint8_t>& shared_key);

    /**
     * @brief 加密数据
     * @param plaintext 明文数据
     * @param ciphertext 密文输出缓冲区
     * @return 是否加密成功
     */
    bool encryptData(const std::vector<uint8_t>& plaintext, 
                    std::vector<uint8_t>& ciphertext);

    /**
     * @brief 解密数据
     * @param ciphertext 密文数据
     * @param plaintext 明文输出缓冲区
     * @return 是否解密成功
     */
    bool decryptData(const std::vector<uint8_t>& ciphertext, 
                    std::vector<uint8_t>& plaintext);

    /**
     * @brief 更新最后活跃时间
     */
    void updateLastActivity();

    /**
     * @brief 获取最后活跃时间
     */
    std::chrono::steady_clock::time_point getLastActivity() const { 
        return last_activity_; 
    }

    /**
     * @brief 检查会话是否过期
     * @param timeout_seconds 超时时间（秒）
     * @return 是否过期
     */
    bool isExpired(int timeout_seconds) const;

    /**
     * @brief 获取会话统计信息
     */
    struct SessionStats {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        std::chrono::steady_clock::time_point created_time;
        std::chrono::steady_clock::time_point last_activity;
    };

    const SessionStats& getStats() const { return stats_; }

    /**
     * @brief 更新发送统计
     */
    void updateSendStats(size_t bytes);

    /**
     * @brief 更新接收统计
     */
    void updateReceiveStats(size_t bytes);

private:
    // 基本信息
    ClientId client_id_;
    struct sockaddr_in endpoint_{};
    std::string virtual_ip_;
    
    // 状态管理
    std::atomic<SessionState> state_{SessionState::CONNECTING};
    std::chrono::steady_clock::time_point last_activity_;
    
    // 认证信息
    AuthInfo auth_info_;
    bool authenticated_{false};
    
    // 加密上下文
    std::unique_ptr<crypto::CryptoContext> crypto_context_;
    bool crypto_initialized_{false};
    
    // 统计信息
    SessionStats stats_;
};

using SessionPtr = std::shared_ptr<ClientSession>;

} // namespace server
} // namespace sduvpn
