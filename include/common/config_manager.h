#pragma once

#include "common/web_server.h"
#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace sduvpn {
namespace common {

/**
 * @brief 通用配置管理器
 * 
 * 负责管理VPN连接配置的保存、加载和加密
 * 支持跨平台的配置文件存储
 */
class ConfigManager : public ConfigManagerInterface {
public:
    ConfigManager();
    virtual ~ConfigManager();

    // 禁用拷贝构造和赋值
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    /**
     * @brief 初始化配置管理器
     * @param config_dir 配置目录路径
     * @return 是否初始化成功
     */
    bool initialize(const std::string& config_dir = "") override;

    /**
     * @brief 保存连接配置
     * @param profile 连接配置
     * @return 是否保存成功
     */
    bool saveProfile(const VPNConnectionProfile& profile) override;

    /**
     * @brief 加载所有连接配置
     * @return 配置列表
     */
    std::vector<VPNConnectionProfile> loadAllProfiles() override;

    /**
     * @brief 根据名称加载配置
     * @param name 配置名称
     * @return 配置项，失败返回nullptr
     */
    std::unique_ptr<VPNConnectionProfile> loadProfile(const std::string& name) override;

    /**
     * @brief 删除配置
     * @param name 配置名称
     * @return 是否删除成功
     */
    bool deleteProfile(const std::string& name) override;

    /**
     * @brief 获取最近使用的配置
     * @param count 返回数量
     * @return 最近使用的配置列表
     */
    std::vector<VPNConnectionProfile> getRecentProfiles(size_t count = 5) override;

    /**
     * @brief 获取收藏的配置
     * @return 收藏的配置列表
     */
    std::vector<VPNConnectionProfile> getFavoriteProfiles() override;

    /**
     * @brief 更新连接统计
     * @param name 配置名称
     * @param success 是否连接成功
     */
    void updateConnectionStats(const std::string& name, bool success) override;

    /**
     * @brief 设置自动连接配置
     * @param name 配置名称
     * @return 是否设置成功
     */
    bool setAutoConnect(const std::string& name) override;

    /**
     * @brief 获取自动连接配置
     * @return 自动连接配置，无则返回nullptr
     */
    std::unique_ptr<VPNConnectionProfile> getAutoConnectProfile() override;

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
    bool profileExists(const std::string& name) override;

    /**
     * @brief 生成唯一的配置名称
     * @param base_name 基础名称
     * @return 唯一名称
     */
    std::string generateUniqueName(const std::string& base_name) override;

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
        const std::string& password) override;

private:
    // 加密相关
    std::string encryptPassword(const std::string& password);
    std::string decryptPassword(const std::string& encrypted_password);
    
    // 文件操作
    std::string getConfigFilePath(const std::string& name);
    std::string getConfigDirectory();
    bool createConfigDirectory();
    bool fileExists(const std::string& path);
    bool deleteFile(const std::string& path);
    std::vector<std::string> listConfigFiles();
    
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

} // namespace common
} // namespace sduvpn
