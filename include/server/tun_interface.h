#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace sduvpn {
namespace server {

/**
 * @brief TUN/TAP接口管理类
 * 
 * 负责创建和管理虚拟网络接口
 */
class TunTapInterface {
public:
    TunTapInterface();
    ~TunTapInterface();

    // 禁用拷贝构造和赋值
    TunTapInterface(const TunTapInterface&) = delete;
    TunTapInterface& operator=(const TunTapInterface&) = delete;

    /**
     * @brief 创建TUN接口
     * @param interface_name 接口名称（如果为空则自动生成）
     * @return 是否创建成功
     */
    bool createTun(const std::string& interface_name = "");

    /**
     * @brief 创建TAP接口
     * @param interface_name 接口名称（如果为空则自动生成）
     * @return 是否创建成功
     */
    bool createTap(const std::string& interface_name = "");

    /**
     * @brief 关闭接口
     */
    void close();

    /**
     * @brief 检查接口是否已打开
     * @return 是否已打开
     */
    bool isOpen() const { return fd_ >= 0; }

    /**
     * @brief 获取接口名称
     * @return 接口名称
     */
    const std::string& getInterfaceName() const { return interface_name_; }

    /**
     * @brief 获取文件描述符
     * @return 文件描述符
     */
    int getFileDescriptor() const { return fd_; }

    /**
     * @brief 设置IP地址和子网掩码
     * @param ip_address IP地址
     * @param netmask 子网掩码
     * @return 是否设置成功
     */
    bool setIPAddress(const std::string& ip_address, const std::string& netmask);

    /**
     * @brief 启用接口
     * @return 是否启用成功
     */
    bool bringUp();

    /**
     * @brief 禁用接口
     * @return 是否禁用成功
     */
    bool bringDown();

    /**
     * @brief 添加路由
     * @param destination 目标网络
     * @param netmask 子网掩码
     * @param gateway 网关（可选）
     * @return 是否添加成功
     */
    bool addRoute(const std::string& destination, 
                  const std::string& netmask,
                  const std::string& gateway = "");

    /**
     * @brief 删除路由
     * @param destination 目标网络
     * @param netmask 子网掩码
     * @return 是否删除成功
     */
    bool removeRoute(const std::string& destination, const std::string& netmask);

    /**
     * @brief 读取数据包
     * @param buffer 数据缓冲区
     * @param buffer_size 缓冲区大小
     * @return 读取的字节数，-1表示错误
     */
    int readPacket(uint8_t* buffer, size_t buffer_size);

    /**
     * @brief 写入数据包
     * @param data 数据
     * @param length 数据长度
     * @return 写入的字节数，-1表示错误
     */
    int writePacket(const uint8_t* data, size_t length);

    /**
     * @brief 设置非阻塞模式
     * @param non_blocking 是否非阻塞
     * @return 是否设置成功
     */
    bool setNonBlocking(bool non_blocking);

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
        uint64_t rx_dropped = 0;
        uint64_t tx_dropped = 0;
    };

    InterfaceStats getStats() const;

    /**
     * @brief 重置统计信息
     */
    void resetStats();

    /**
     * @brief 设置数据包处理回调函数
     * @param callback 回调函数
     */
    using PacketCallback = std::function<void(const uint8_t*, size_t)>;
    void setPacketCallback(const PacketCallback& callback) {
        packet_callback_ = callback;
    }

private:
    /**
     * @brief 创建接口的通用实现
     * @param is_tun 是否为TUN接口（false为TAP）
     * @param interface_name 接口名称
     * @return 是否创建成功
     */
    bool createInterface(bool is_tun, const std::string& interface_name);

    /**
     * @brief 执行系统命令
     * @param command 命令
     * @return 是否执行成功
     */
    bool executeCommand(const std::string& command);

    /**
     * @brief 更新统计信息
     * @param rx_bytes 接收字节数
     * @param tx_bytes 发送字节数
     */
    void updateStats(size_t rx_bytes, size_t tx_bytes);

private:
    int fd_;                        // 文件描述符
    std::string interface_name_;    // 接口名称
    bool is_tun_;                   // 是否为TUN接口
    std::string ip_address_;        // IP地址
    std::string netmask_;           // 子网掩码
    
    // 统计信息
    mutable InterfaceStats stats_;
    
    // 回调函数
    PacketCallback packet_callback_;
};

} // namespace server
} // namespace sduvpn
