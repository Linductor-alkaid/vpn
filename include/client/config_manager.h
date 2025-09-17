#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace sduvpn {
namespace client {

/**
 * @brief VPN连接配置项
 */
struct VPNConnectionProfile {
    std::string name;                    // 配置名称
    std::string server_address;          // 服务器地址
    uint16_t server_port = 1194;        // 服务器端口
    std::string username;                // 用户名
    std::string password;                // 密码（加密存储）
    std::string tap_adapter_name;        // TAP适配器名称
    std::string virtual_ip;              // 虚拟IP
    std::string virtual_netmask = "255.255.255.0"; // 子网掩码
    uint32_t keepalive_interval = 30;    // 保活间隔
    uint32_t connection_timeout = 10;    // 连接超时
    bool auto_reconnect = true;          // 自动重连
    uint32_t max_reconnect_attempts = 5; // 最大重连次数
    
    // 统计信息
    uint32_t connection_count = 0;       // 连接次数
    std::string last_connected;          // 最后连接时间
    std::string created_time;            // 创建时间
    
    // 标记
    bool is_favorite = false;            // 是否收藏
    bool auto_connect = false;           // 自动连接
};

/**
 * @brief 配置管理器
 * 
 * 负责管理VPN连接配置的保存、加载和加密
 */
class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();

    // 禁用拷贝构造和赋值
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    /**
     * @brief 初始化配置管理器
     * @param config_dir 配置目录路径
     * @return 是否初始化成功
     */
    bool initialize(const std::string& config_dir = "");

    /**
     * @brief 保存连接配置
     * @param profile 连接配置
     * @return 是否保存成功
     */
    bool saveProfile(const VPNConnectionProfile& profile);

    /**
     * @brief 加载所有连接配置
     * @return 配置列表
     */
    std::vector<VPNConnectionProfile> loadAllProfiles();

    /**
     * @brief 根据名称加载配置
     * @param name 配置名称
     * @return 配置项，失败返回nullptr
     */
    std::unique_ptr<VPNConnectionProfile> loadProfile(const std::string& name);

    /**
     * @brief 删除配置
     * @param name 配置名称
     * @return 是否删除成功
     */
    bool deleteProfile(const std::string& name);

    /**
     * @brief 获取最近使用的配置
     * @param count 返回数量
     * @return 最近使用的配置列表
     */
    std::vector<VPNConnectionProfile> getRecentProfiles(size_t count = 5);

    /**
     * @brief 获取收藏的配置
     * @return 收藏的配置列表
     */
    std::vector<VPNConnectionProfile> getFavoriteProfiles();

    /**
     * @brief 更新连接统计
     * @param name 配置名称
     * @param success 是否连接成功
     */
    void updateConnectionStats(const std::string& name, bool success);

    /**
     * @brief 设置自动连接配置
     * @param name 配置名称
     * @return 是否设置成功
     */
    bool setAutoConnect(const std::string& name);

    /**
     * @brief 获取自动连接配置
     * @return 自动连接配置，无则返回nullptr
     */
    std::unique_ptr<VPNConnectionProfile> getAutoConnectProfile();

    /**
     * @brief 导入配置文件
     * @param file_path 配置文件路径
     * @return 是否导入成功
     */
    bool importConfig(const std::string& file_path);

    /**
     * @brief 导出配置文件
     * @param file_path 导出文件路径
     * @param profile_names 要导出的配置名称列表
     * @return 是否导出成功
     */
    bool exportConfig(const std::string& file_path, const std::vector<std::string>& profile_names);

    /**
     * @brief 检查配置名称是否存在
     * @param name 配置名称
     * @return 是否存在
     */
    bool profileExists(const std::string& name);

    /**
     * @brief 生成唯一的配置名称
     * @param base_name 基础名称
     * @return 唯一名称
     */
    std::string generateUniqueName(const std::string& base_name);

    /**
     * @brief 查找具有相同登录数据的配置
     * @param server_address 服务器地址
     * @param username 用户名
     * @param password 密码
     * @return 匹配的配置，没有则返回nullptr
     */
    std::unique_ptr<VPNConnectionProfile> findProfileByLoginData(
        const std::string& server_address, 
        const std::string& username, 
        const std::string& password);

private:
    // 加密相关
    std::string encryptPassword(const std::string& password);
    std::string decryptPassword(const std::string& encrypted_password);
    
    // 文件操作
    std::string getConfigFilePath(const std::string& name);
    std::string getConfigDirectory();
    bool createConfigDirectory();
    
    // JSON序列化
    std::string profileToJson(const VPNConnectionProfile& profile);
    std::unique_ptr<VPNConnectionProfile> profileFromJson(const std::string& json);
    
    // 工具函数
    std::string getCurrentTimeString();
    std::string sanitizeFileName(const std::string& name);

private:
    std::string config_dir_;
    mutable std::mutex config_mutex_;
    
    // 简单的加密密钥（在生产环境中应使用更安全的密钥管理）
    static constexpr const char* ENCRYPTION_KEY = "SDUVPN_CONFIG_KEY_2024";
};

// 配置辅助函数将在cpp文件中实现，避免循环依赖

} // namespace client
} // namespace sduvpn
