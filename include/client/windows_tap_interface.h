#pragma once

#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>

namespace sduvpn {
namespace client {

/**
 * @brief Windows TAP适配器接口类
 * 
 * 负责与Windows TAP虚拟网卡驱动程序交互
 */
class WindowsTapInterface {
public:
    WindowsTapInterface();
    ~WindowsTapInterface();

    // 禁用拷贝构造和赋值
    WindowsTapInterface(const WindowsTapInterface&) = delete;
    WindowsTapInterface& operator=(const WindowsTapInterface&) = delete;

    /**
     * @brief 查找并打开TAP适配器
     * @param adapter_name 适配器名称(可选，为空则自动查找)
     * @return 是否成功
     */
    bool openAdapter(const std::string& adapter_name = "");

    /**
     * @brief 关闭TAP适配器
     */
    void closeAdapter();

    /**
     * @brief 检查适配器是否已打开
     * @return 是否已打开
     */
    bool isOpen() const { return tap_handle_ != INVALID_HANDLE_VALUE; }

    /**
     * @brief 设置TAP适配器IP地址
     * @param ip_address IP地址
     * @param subnet_mask 子网掩码
     * @param gateway 网关地址(可选)
     * @return 是否成功
     */
    bool setIPAddress(const std::string& ip_address, 
                     const std::string& subnet_mask,
                     const std::string& gateway = "");

    /**
     * @brief 设置TAP适配器状态
     * @param connected 是否连接状态
     * @return 是否成功
     */
    bool setAdapterStatus(bool connected);

    /**
     * @brief 读取数据包
     * @param buffer 接收缓冲区
     * @param buffer_size 缓冲区大小
     * @param bytes_read 实际读取字节数
     * @return 是否成功
     */
    bool readPacket(uint8_t* buffer, size_t buffer_size, DWORD* bytes_read);

    /**
     * @brief 写入数据包
     * @param buffer 发送缓冲区
     * @param buffer_size 数据大小
     * @param bytes_written 实际写入字节数
     * @return 是否成功
     */
    bool writePacket(const uint8_t* buffer, size_t buffer_size, DWORD* bytes_written);

    /**
     * @brief 获取适配器名称
     * @return 适配器名称
     */
    const std::string& getAdapterName() const { return adapter_name_; }

    /**
     * @brief 获取适配器GUID
     * @return 适配器GUID
     */
    const std::string& getAdapterGUID() const { return adapter_guid_; }

    /**
     * @brief 获取错误信息
     * @return 错误信息
     */
    const std::string& getLastError() const { return last_error_; }

    /**
     * @brief 获取统计信息
     */
    struct Statistics {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
    };

    Statistics getStatistics() const;

public:
    // TAP适配器相关常量 - 需要被TapAdapterManager访问
    static constexpr const char* TAP_COMPONENT_ID = "tap0901";
    static constexpr const char* ADAPTER_KEY = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    static constexpr const char* NETWORK_CONNECTIONS_KEY = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";

private:

    // TAP IOCTL控制码
    static constexpr DWORD TAP_IOCTL_GET_MAC = CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_GET_VERSION = CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_GET_MTU = CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_GET_INFO = CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_CONFIG_POINT_TO_POINT = CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_SET_MEDIA_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_CONFIG_DHCP_MASQ = CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_GET_LOG_LINE = CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static constexpr DWORD TAP_IOCTL_CONFIG_DHCP_SET_OPT = CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);

    // 内部方法
    std::vector<std::string> findTapAdapters();
    bool openAdapterByGuid(const std::string& guid);
    bool getAdapterInfo(const std::string& guid, std::string& name);
    std::string guidToDeviceName(const std::string& guid);
    bool executeNetshCommand(const std::string& command);
    void setLastError(const std::string& error);

private:
    HANDLE tap_handle_;
    std::string adapter_name_;
    std::string adapter_guid_;
    std::string last_error_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    Statistics stats_;
};

/**
 * @brief TAP适配器管理器
 * 
 * 用于管理系统中的TAP适配器
 */
class TapAdapterManager {
public:
    /**
     * @brief 获取所有可用的TAP适配器
     * @return 适配器GUID列表
     */
    static std::vector<std::string> getAvailableAdapters();

    /**
     * @brief 检查TAP驱动是否已安装
     * @return 是否已安装
     */
    static bool isTapDriverInstalled();

    /**
     * @brief 获取TAP驱动版本
     * @return 驱动版本字符串
     */
    static std::string getTapDriverVersion();

    /**
     * @brief 安装TAP驱动
     * @param driver_path 驱动程序路径
     * @return 是否成功
     */
    static bool installTapDriver(const std::string& driver_path);

    /**
     * @brief 卸载TAP驱动
     * @return 是否成功
     */
    static bool uninstallTapDriver();
};

} // namespace client
} // namespace sduvpn
