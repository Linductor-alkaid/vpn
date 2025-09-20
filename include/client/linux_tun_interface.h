#pragma once

#include <string>
#include <memory>
#include <vector>

namespace sduvpn {
namespace client {

/**
 * @brief Linux TUN接口管理器
 * 
 * 负责创建、配置和管理Linux TUN网络接口
 */
class LinuxTunInterface {
public:
    LinuxTunInterface();
    ~LinuxTunInterface();

    // 禁用拷贝构造和赋值
    LinuxTunInterface(const LinuxTunInterface&) = delete;
    LinuxTunInterface& operator=(const LinuxTunInterface&) = delete;

    /**
     * @brief 打开TUN接口
     * @param interface_name 接口名称（可选，为空则自动分配）
     * @return 是否成功
     */
    bool openInterface(const std::string& interface_name = "");

    /**
     * @brief 关闭TUN接口
     */
    void closeInterface();

    /**
     * @brief 设置IP地址
     * @param ip_address IP地址
     * @param netmask 子网掩码
     * @return 是否成功
     */
    bool setIPAddress(const std::string& ip_address, const std::string& netmask);

    /**
     * @brief 设置接口状态
     * @param up true为启用，false为禁用
     * @return 是否成功
     */
    bool setInterfaceStatus(bool up);

    /**
     * @brief 添加路由
     * @param destination 目标网络
     * @param netmask 子网掩码
     * @param gateway 网关（可选）
     * @return 是否成功
     */
    bool addRoute(const std::string& destination, const std::string& netmask, const std::string& gateway = "");

    /**
     * @brief 删除路由
     * @param destination 目标网络
     * @param netmask 子网掩码
     * @return 是否成功
     */
    bool removeRoute(const std::string& destination, const std::string& netmask);

    /**
     * @brief 读取数据包
     * @param buffer 缓冲区
     * @param buffer_size 缓冲区大小
     * @param bytes_read 实际读取的字节数
     * @return 是否成功
     */
    bool readPacket(uint8_t* buffer, size_t buffer_size, size_t* bytes_read);

    /**
     * @brief 写入数据包
     * @param data 数据
     * @param length 数据长度
     * @param bytes_written 实际写入的字节数
     * @return 是否成功
     */
    bool writePacket(const uint8_t* data, size_t length, size_t* bytes_written);

    /**
     * @brief 获取接口名称
     */
    std::string getInterfaceName() const { return interface_name_; }

    /**
     * @brief 获取文件描述符
     */
    int getFileDescriptor() const { return tun_fd_; }

    /**
     * @brief 检查接口是否打开
     */
    bool isOpen() const { return tun_fd_ >= 0; }

    /**
     * @brief 获取最后的错误信息
     */
    std::string getLastError() const { return last_error_; }

    /**
     * @brief 获取接口统计信息
     */
    struct InterfaceStats {
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
    };
    
    InterfaceStats getStats() const;

public:
    // 静态工具函数
    
    /**
     * @brief 检查TUN模块是否可用
     */
    static bool isTunModuleAvailable();

    /**
     * @brief 获取可用的TUN接口列表
     */
    static std::vector<std::string> getAvailableInterfaces();

    /**
     * @brief 检查是否有root权限
     */
    static bool hasRootPrivileges();

private:
    // 工具函数
    bool createTunDevice();
    bool configureInterface();
    bool executeCommand(const std::string& command);
    void setLastError(const std::string& error);
    
    // IP地址转换
    uint32_t ipStringToInt(const std::string& ip);
    std::string ipIntToString(uint32_t ip);
    int netmaskToCIDR(const std::string& netmask);

private:
    int tun_fd_{-1};
    std::string interface_name_;
    std::string ip_address_;
    std::string netmask_;
    bool interface_up_{false};
    std::string last_error_;
    
    // 统计信息
    mutable InterfaceStats stats_;
};

/**
 * @brief TUN接口管理器
 * 
 * 提供系统级的TUN接口管理功能
 */
class TunInterfaceManager {
public:
    /**
     * @brief 检查TUN模块是否已加载
     */
    static bool isTunModuleLoaded();

    /**
     * @brief 加载TUN模块
     */
    static bool loadTunModule();

    /**
     * @brief 获取系统TUN接口信息
     */
    static std::vector<std::string> getSystemTunInterfaces();

    /**
     * @brief 检查接口是否存在
     */
    static bool interfaceExists(const std::string& name);

    /**
     * @brief 获取接口IP地址
     */
    static std::string getInterfaceIP(const std::string& name);

    /**
     * @brief 获取接口状态
     */
    static bool getInterfaceStatus(const std::string& name);
};

} // namespace client
} // namespace sduvpn
