#include "server/packet_router.h"
#include "server/client_session.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace sduvpn {
namespace server {

std::string IPHeader::getSourceIP() const {
    struct in_addr addr;
    addr.s_addr = source_ip;
    return std::string(inet_ntoa(addr));
}

std::string IPHeader::getDestIP() const {
    struct in_addr addr;
    addr.s_addr = dest_ip;
    return std::string(inet_ntoa(addr));
}

PacketRouter::PacketRouter() 
    : virtual_network_uint_(0)
    , virtual_netmask_uint_(0)
    , debug_mode_(false) {
    std::memset(&stats_, 0, sizeof(stats_));
}

bool PacketRouter::initialize(const std::string& virtual_network, 
                             const std::string& virtual_netmask) {
    virtual_network_ = virtual_network;
    virtual_netmask_ = virtual_netmask;
    
    // 转换为32位整数格式
    virtual_network_uint_ = ipStringToUint32(virtual_network);
    virtual_netmask_uint_ = ipStringToUint32(virtual_netmask);
    
    if (virtual_network_uint_ == 0 || virtual_netmask_uint_ == 0) {
        std::cerr << "Invalid virtual network configuration: " << virtual_network << "/" << virtual_netmask << std::endl;
        return false;
    }
    
    // 添加默认的虚拟网络路由
    RouteEntry virtual_route(virtual_network, virtual_netmask, "", "", 0, 0);
    static_routes_.push_back(virtual_route);
    
    std::cout << "Router initialized, virtual network: " << virtual_network << "/" << virtual_netmask << std::endl;
    
    return true;
}

void PacketRouter::addClientRoute(ClientId client_id, const std::string& virtual_ip, 
                                 SessionPtr session) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    // 创建客户端路由条目
    RouteEntry route(virtual_ip, "255.255.255.255", "", "", 1, client_id);
    
    client_routes_[client_id] = route;
    ip_to_client_[virtual_ip] = client_id;
    client_sessions_[client_id] = session;
    
    if (debug_mode_) {
        std::cout << "Add client route: " << virtual_ip << " -> client " << client_id << std::endl;
    }
}

void PacketRouter::removeClientRoute(ClientId client_id) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    auto it = client_routes_.find(client_id);
    if (it != client_routes_.end()) {
        const std::string& virtual_ip = it->second.network;
        
        client_routes_.erase(it);
        ip_to_client_.erase(virtual_ip);
        client_sessions_.erase(client_id);
        
        if (debug_mode_) {
            std::cout << "Remove client route: " << virtual_ip << " -> client " << client_id << std::endl;
        }
    }
    
    // 额外的安全措施：遍历ip_to_client_映射，删除指向该客户端的所有条目
    for (auto it = ip_to_client_.begin(); it != ip_to_client_.end(); ) {
        if (it->second == client_id) {
            it = ip_to_client_.erase(it);
        } else {
            ++it;
        }
    }
}

bool PacketRouter::addStaticRoute(const RouteEntry& route) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    // 检查是否已存在相同的路由
    auto it = std::find_if(static_routes_.begin(), static_routes_.end(),
                          [&route](const RouteEntry& existing) {
                              return existing.network == route.network && 
                                     existing.netmask == route.netmask;
                          });
    
    if (it != static_routes_.end()) {
        // 更新现有路由
        *it = route;
    } else {
        // 添加新路由
        static_routes_.push_back(route);
    }
    
    if (debug_mode_) {
        std::cout << "Add static route: " << route.network << "/" << route.netmask;
        if (!route.gateway.empty()) {
            std::cout << " via " << route.gateway;
        }
        std::cout << std::endl;
    }
    
    return true;
}

bool PacketRouter::removeStaticRoute(const std::string& network, const std::string& netmask) {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    auto it = std::find_if(static_routes_.begin(), static_routes_.end(),
                          [&network, &netmask](const RouteEntry& route) {
                              return route.network == network && route.netmask == netmask;
                          });
    
    if (it != static_routes_.end()) {
        static_routes_.erase(it);
        
        if (debug_mode_) {
            std::cout << "Remove static route: " << network << "/" << netmask << std::endl;
        }
        
        return true;
    }
    
    return false;
}

PacketRouter::RoutingResult PacketRouter::routePacket(const uint8_t* packet, size_t packet_size) {
    RoutingResult result;
    
    // 解析IP数据包头
    const IPHeader* ip_header = parseIPHeader(packet, packet_size);
    if (!ip_header) {
        result.action = RoutingResult::DROP;
        result.reason = "无效的IP数据包";
        updateStats(result.action);
        return result;
    }
    
    std::string dest_ip = ip_header->getDestIP();
    std::string src_ip = ip_header->getSourceIP();
    
    if (debug_mode_) {
        std::cout << "Route packet: " << src_ip << " -> " << dest_ip << std::endl;
    }
    
    // Check if destination IP is in virtual network or is a broadcast address
    bool is_virtual_network = isInVirtualNetwork(dest_ip);
    bool is_broadcast = (dest_ip == "255.255.255.255" || dest_ip == "10.8.0.255"); // 添加广播地址检查
    
    if (!is_virtual_network && !is_broadcast) {
        result.action = RoutingResult::DROP;
        result.reason = "Destination IP not in virtual network";
        updateStats(result.action);
        return result;
    }
    
    // Find target client
    ClientId target_client = findClientByIP(dest_ip);
    if (target_client != 0) {
        // Forward to specific client
        std::lock_guard<std::mutex> lock(route_mutex_);
        auto session_it = client_sessions_.find(target_client);
        if (session_it != client_sessions_.end()) {
            result.action = RoutingResult::TO_CLIENT;
            result.target_client = target_client;
            result.target_session = session_it->second;
            result.reason = "Forward to client " + std::to_string(target_client);
        } else {
            result.action = RoutingResult::DROP;
            result.reason = "Client session not found";
        }
    } else {
        // Check if it's a broadcast address
        uint32_t dest_ip_uint = ipStringToUint32(dest_ip);
        uint32_t broadcast_addr = (virtual_network_uint_ & virtual_netmask_uint_) | (~virtual_netmask_uint_);
        
        if (dest_ip_uint == broadcast_addr || dest_ip_uint == 0xFFFFFFFF) {
            // Broadcast packet
            result.action = RoutingResult::BROADCAST;
            result.reason = "Broadcast packet";
        } else {
            // Forward to TUN interface (local processing)
            result.action = RoutingResult::TO_TUN;
            result.reason = "Forward to TUN interface";
        }
    }
    
    updateStats(result.action);
    return result;
}

const RouteEntry* PacketRouter::findRoute(const std::string& dest_ip) const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    uint32_t dest_ip_uint = ipStringToUint32(dest_ip);
    
    // 首先查找客户端路由（主机路由，优先级最高）
    for (const auto& pair : client_routes_) {
        const RouteEntry& route = pair.second;
        uint32_t network_uint = ipStringToUint32(route.network);
        uint32_t netmask_uint = ipStringToUint32(route.netmask);
        
        if ((dest_ip_uint & netmask_uint) == (network_uint & netmask_uint)) {
            return &route;
        }
    }
    
    // 然后查找静态路由
    for (const auto& route : static_routes_) {
        uint32_t network_uint = ipStringToUint32(route.network);
        uint32_t netmask_uint = ipStringToUint32(route.netmask);
        
        if ((dest_ip_uint & netmask_uint) == (network_uint & netmask_uint)) {
            return &route;
        }
    }
    
    return nullptr;
}

std::vector<RouteEntry> PacketRouter::getRouteTable() const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    std::vector<RouteEntry> routes;
    
    // 添加静态路由
    routes.insert(routes.end(), static_routes_.begin(), static_routes_.end());
    
    // 添加客户端路由
    for (const auto& pair : client_routes_) {
        routes.push_back(pair.second);
    }
    
    // 按照度量值排序
    std::sort(routes.begin(), routes.end(), 
             [](const RouteEntry& a, const RouteEntry& b) {
                 return a.metric < b.metric;
             });
    
    return routes;
}

SessionPtr PacketRouter::getClientSession(ClientId client_id) const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    auto it = client_sessions_.find(client_id);
    if (it != client_sessions_.end()) {
        return it->second;
    }
    
    return nullptr;
}

ClientId PacketRouter::findClientByIP(const std::string& ip_address) const {
    std::lock_guard<std::mutex> lock(route_mutex_);
    
    auto it = ip_to_client_.find(ip_address);
    if (it != ip_to_client_.end()) {
        return it->second;
    }
    
    return 0;
}

bool PacketRouter::isInVirtualNetwork(const std::string& ip_address) const {
    uint32_t ip_uint = ipStringToUint32(ip_address);
    return (ip_uint & virtual_netmask_uint_) == (virtual_network_uint_ & virtual_netmask_uint_);
}

void PacketRouter::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::memset(&stats_, 0, sizeof(stats_));
}

const IPHeader* PacketRouter::parseIPHeader(const uint8_t* packet, size_t packet_size) const {
    if (packet_size < sizeof(IPHeader)) {
        return nullptr;
    }
    
    const IPHeader* header = reinterpret_cast<const IPHeader*>(packet);
    
    // 验证IP版本
    if (header->getVersion() != 4) {
        return nullptr;
    }
    
    // 验证头长度
    if (header->getHeaderLength() < 20 || header->getHeaderLength() > packet_size) {
        return nullptr;
    }
    
    return header;
}

bool PacketRouter::isIPInNetwork(const std::string& ip_address, 
                                const std::string& network,
                                const std::string& netmask) const {
    uint32_t ip_uint = ipStringToUint32(ip_address);
    uint32_t network_uint = ipStringToUint32(network);
    uint32_t netmask_uint = ipStringToUint32(netmask);
    
    return (ip_uint & netmask_uint) == (network_uint & netmask_uint);
}

uint32_t PacketRouter::ipStringToUint32(const std::string& ip_str) const {
#ifdef _WIN32
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return 0;
    }
    return addr.s_addr;
#else
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0) {
        return 0;
    }
    return addr.s_addr;
#endif
}

std::string PacketRouter::uint32ToIPString(uint32_t ip_uint) const {
    struct in_addr addr;
    addr.s_addr = ip_uint;
    return std::string(inet_ntoa(addr));
}

void PacketRouter::updateStats(RoutingResult::Action action) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.packets_routed++;
    
    switch (action) {
        case RoutingResult::DROP:
            stats_.packets_dropped++;
            break;
        case RoutingResult::TO_CLIENT:
            stats_.packets_to_client++;
            break;
        case RoutingResult::TO_TUN:
            stats_.packets_to_tun++;
            break;
        case RoutingResult::BROADCAST:
            stats_.packets_broadcast++;
            break;
    }
}

} // namespace server
} // namespace sduvpn
