#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>
#include <cstdint>

namespace sduvpn {
namespace server {

// 前向声明
class ClientSession;
using ClientId = uint32_t;
using SessionPtr = std::shared_ptr<ClientSession>;

/**
 * @brief IP数据包头结构（简化版）
 */
#ifdef _WIN32
#pragma pack(push, 1)
#endif
struct IPHeader {
    uint8_t version_ihl;        // 版本和头长度
    uint8_t tos;                // 服务类型
    uint16_t total_length;      // 总长度
    uint16_t identification;    // 标识
    uint16_t flags_fragment;    // 标志和片偏移
    uint8_t ttl;                // 生存时间
    uint8_t protocol;           // 协议
    uint16_t checksum;          // 头校验和
    uint32_t source_ip;         // 源IP地址
    uint32_t dest_ip;           // 目的IP地址
    
    // 辅助方法
    uint8_t getVersion() const { return (version_ihl >> 4) & 0x0F; }
    uint8_t getHeaderLength() const { return (version_ihl & 0x0F) * 4; }
    std::string getSourceIP() const;
    std::string getDestIP() const;
}
#ifdef _WIN32
#pragma pack(pop)
#endif
;

/**
 * @brief 路由表条目
 */
struct RouteEntry {
    std::string network;        // 网络地址
    std::string netmask;        // 子网掩码
    std::string gateway;        // 网关
    std::string interface;      // 接口名称
    uint32_t metric;            // 路由度量
    ClientId client_id;         // 关联的客户端ID（0表示本地路由）
    
    RouteEntry() : metric(0), client_id(0) {}
    RouteEntry(const std::string& net, const std::string& mask, 
              const std::string& gw = "", const std::string& iface = "",
              uint32_t met = 0, ClientId cid = 0)
        : network(net), netmask(mask), gateway(gw), interface(iface), 
          metric(met), client_id(cid) {}
};

/**
 * @brief 数据包路由器
 * 
 * 负责处理数据包的路由和转发决策
 */
class PacketRouter {
public:
    PacketRouter();
    ~PacketRouter() = default;

    // 禁用拷贝构造和赋值
    PacketRouter(const PacketRouter&) = delete;
    PacketRouter& operator=(const PacketRouter&) = delete;

    /**
     * @brief 初始化路由器
     * @param virtual_network 虚拟网络地址
     * @param virtual_netmask 虚拟网络掩码
     * @return 是否初始化成功
     */
    bool initialize(const std::string& virtual_network, 
                   const std::string& virtual_netmask);

    /**
     * @brief 添加客户端路由
     * @param client_id 客户端ID
     * @param virtual_ip 客户端虚拟IP
     * @param session 客户端会话
     */
    void addClientRoute(ClientId client_id, const std::string& virtual_ip, 
                       SessionPtr session);

    /**
     * @brief 删除客户端路由
     * @param client_id 客户端ID
     */
    void removeClientRoute(ClientId client_id);

    /**
     * @brief 添加静态路由
     * @param route 路由条目
     * @return 是否添加成功
     */
    bool addStaticRoute(const RouteEntry& route);

    /**
     * @brief 删除静态路由
     * @param network 网络地址
     * @param netmask 子网掩码
     * @return 是否删除成功
     */
    bool removeStaticRoute(const std::string& network, const std::string& netmask);

    /**
     * @brief 路由数据包
     * @param packet 数据包
     * @param packet_size 数据包大小
     * @return 路由决策结果
     */
    struct RoutingResult {
        enum Action {
            DROP,           // 丢弃数据包
            TO_CLIENT,      // 转发给客户端
            TO_TUN,         // 转发给TUN接口
            BROADCAST       // 广播给所有客户端
        } action = DROP;
        
        ClientId target_client = 0;     // 目标客户端ID（如果action为TO_CLIENT）
        SessionPtr target_session;      // 目标会话（如果action为TO_CLIENT）
        std::string reason;             // 路由决策原因
    };

    RoutingResult routePacket(const uint8_t* packet, size_t packet_size);

    /**
     * @brief 查找路由
     * @param dest_ip 目标IP地址
     * @return 路由条目指针，nullptr表示未找到
     */
    const RouteEntry* findRoute(const std::string& dest_ip) const;

    /**
     * @brief 获取所有路由条目
     * @return 路由表
     */
    std::vector<RouteEntry> getRouteTable() const;

    /**
     * @brief 获取客户端会话
     * @param client_id 客户端ID
     * @return 会话指针
     */
    SessionPtr getClientSession(ClientId client_id) const;

    /**
     * @brief 根据IP地址查找客户端
     * @param ip_address IP地址
     * @return 客户端ID，0表示未找到
     */
    ClientId findClientByIP(const std::string& ip_address) const;

    /**
     * @brief 检查IP地址是否在虚拟网络中
     * @param ip_address IP地址
     * @return 是否在虚拟网络中
     */
    bool isInVirtualNetwork(const std::string& ip_address) const;

    /**
     * @brief 获取路由统计信息
     */
    struct RoutingStats {
        uint64_t packets_routed = 0;
        uint64_t packets_dropped = 0;
        uint64_t packets_to_client = 0;
        uint64_t packets_to_tun = 0;
        uint64_t packets_broadcast = 0;
        uint64_t routing_errors = 0;
    };

    const RoutingStats& getStats() const { return stats_; }
    void resetStats();

    /**
     * @brief 设置调试模式
     * @param debug 是否启用调试
     */
    void setDebugMode(bool debug) { debug_mode_ = debug; }

private:
    /**
     * @brief 解析IP数据包头
     * @param packet 数据包
     * @param packet_size 数据包大小
     * @return IP头指针，nullptr表示解析失败
     */
    const IPHeader* parseIPHeader(const uint8_t* packet, size_t packet_size) const;

    /**
     * @brief 检查IP地址是否匹配网络
     * @param ip_address IP地址
     * @param network 网络地址
     * @param netmask 子网掩码
     * @return 是否匹配
     */
    bool isIPInNetwork(const std::string& ip_address, 
                      const std::string& network,
                      const std::string& netmask) const;

    /**
     * @brief IP地址字符串转换为32位整数
     * @param ip_str IP地址字符串
     * @return 32位整数表示的IP地址
     */
    uint32_t ipStringToUint32(const std::string& ip_str) const;

    /**
     * @brief 32位整数转换为IP地址字符串
     * @param ip_uint 32位整数表示的IP地址
     * @return IP地址字符串
     */
    std::string uint32ToIPString(uint32_t ip_uint) const;

    /**
     * @brief 更新统计信息
     * @param action 路由动作
     */
    void updateStats(RoutingResult::Action action);

private:
    // 路由表
    mutable std::mutex route_mutex_;
    std::vector<RouteEntry> static_routes_;         // 静态路由
    std::unordered_map<ClientId, RouteEntry> client_routes_;  // 客户端路由
    std::unordered_map<std::string, ClientId> ip_to_client_;  // IP到客户端映射
    std::unordered_map<ClientId, SessionPtr> client_sessions_;  // 客户端会话

    // 虚拟网络配置
    std::string virtual_network_;
    std::string virtual_netmask_;
    uint32_t virtual_network_uint_;
    uint32_t virtual_netmask_uint_;

    // 统计信息
    mutable std::mutex stats_mutex_;
    RoutingStats stats_;

    // 调试模式
    bool debug_mode_;
};

} // namespace server
} // namespace sduvpn
