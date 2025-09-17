#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace sduvpn {
namespace server {

/**
 * @brief 服务器配置类
 * 
 * 管理服务器的各种配置参数
 */
class ServerConfig {
public:
    ServerConfig();
    ~ServerConfig() = default;

    /**
     * @brief 从JSON文件加载配置
     * @param config_file 配置文件路径
     * @return 是否加载成功
     */
    bool loadFromFile(const std::string& config_file);

    /**
     * @brief 从JSON字符串加载配置
     * @param json_str JSON字符串
     * @return 是否加载成功
     */
    bool loadFromString(const std::string& json_str);

    /**
     * @brief 保存配置到文件
     * @param config_file 配置文件路径
     * @return 是否保存成功
     */
    bool saveToFile(const std::string& config_file) const;

    /**
     * @brief 验证配置的有效性
     * @return 是否有效
     */
    bool validate() const;

    // 网络配置
    uint16_t getListenPort() const { return listen_port_; }
    void setListenPort(uint16_t port) { listen_port_ = port; }

    const std::string& getBindAddress() const { return bind_address_; }
    void setBindAddress(const std::string& addr) { bind_address_ = addr; }

    // 虚拟网络配置
    const std::string& getVirtualNetwork() const { return virtual_network_; }
    void setVirtualNetwork(const std::string& network) { virtual_network_ = network; }

    const std::string& getVirtualNetmask() const { return virtual_netmask_; }
    void setVirtualNetmask(const std::string& netmask) { virtual_netmask_ = netmask; }

    const std::string& getTunInterfaceName() const { return tun_interface_name_; }
    void setTunInterfaceName(const std::string& name) { tun_interface_name_ = name; }

    // 客户端管理
    uint32_t getMaxClients() const { return max_clients_; }
    void setMaxClients(uint32_t max_clients) { max_clients_ = max_clients; }

    uint32_t getClientTimeoutSeconds() const { return client_timeout_seconds_; }
    void setClientTimeoutSeconds(uint32_t timeout) { client_timeout_seconds_ = timeout; }

    // 安全配置
    const std::string& getServerCertificate() const { return server_certificate_; }
    void setServerCertificate(const std::string& cert) { server_certificate_ = cert; }

    const std::string& getServerPrivateKey() const { return server_private_key_; }
    void setServerPrivateKey(const std::string& key) { server_private_key_ = key; }

    const std::string& getCACertificate() const { return ca_certificate_; }
    void setCACertificate(const std::string& ca) { ca_certificate_ = ca; }

    // 认证配置
    bool isAuthenticationRequired() const { return require_authentication_; }
    void setAuthenticationRequired(bool required) { require_authentication_ = required; }

    const std::vector<std::pair<std::string, std::string>>& getUsers() const { 
        return users_; 
    }
    void addUser(const std::string& username, const std::string& password);
    void removeUser(const std::string& username);
    bool verifyUser(const std::string& username, const std::string& password) const;

    // 日志配置
    const std::string& getLogLevel() const { return log_level_; }
    void setLogLevel(const std::string& level) { log_level_ = level; }

    const std::string& getLogFile() const { return log_file_; }
    void setLogFile(const std::string& file) { log_file_ = file; }

    bool isLogToConsole() const { return log_to_console_; }
    void setLogToConsole(bool enable) { log_to_console_ = enable; }

    // 性能配置
    uint32_t getWorkerThreads() const { return worker_threads_; }
    void setWorkerThreads(uint32_t threads) { worker_threads_ = threads; }

    uint32_t getReceiveBufferSize() const { return receive_buffer_size_; }
    void setReceiveBufferSize(uint32_t size) { receive_buffer_size_ = size; }

    uint32_t getSendBufferSize() const { return send_buffer_size_; }
    void setSendBufferSize(uint32_t size) { send_buffer_size_ = size; }

    // 调试配置
    bool isDebugMode() const { return debug_mode_; }
    void setDebugMode(bool debug) { debug_mode_ = debug; }

    bool isPacketDumpEnabled() const { return enable_packet_dump_; }
    void setPacketDumpEnabled(bool enable) { enable_packet_dump_ = enable; }

private:
    // 网络配置
    uint16_t listen_port_;
    std::string bind_address_;

    // 虚拟网络配置
    std::string virtual_network_;
    std::string virtual_netmask_;
    std::string tun_interface_name_;

    // 客户端管理
    uint32_t max_clients_;
    uint32_t client_timeout_seconds_;

    // 安全配置
    std::string server_certificate_;
    std::string server_private_key_;
    std::string ca_certificate_;

    // 认证配置
    bool require_authentication_;
    std::vector<std::pair<std::string, std::string>> users_; // username, password pairs

    // 日志配置
    std::string log_level_;
    std::string log_file_;
    bool log_to_console_;

    // 性能配置
    uint32_t worker_threads_;
    uint32_t receive_buffer_size_;
    uint32_t send_buffer_size_;

    // 调试配置
    bool debug_mode_;
    bool enable_packet_dump_;

    /**
     * @brief 设置默认配置值
     */
    void setDefaults();
};

} // namespace server
} // namespace sduvpn
