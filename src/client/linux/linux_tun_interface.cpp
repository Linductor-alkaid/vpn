#include "client/linux_tun_interface.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fstream>
#include <vector>
#include <algorithm>

namespace sduvpn {
namespace client {

LinuxTunInterface::LinuxTunInterface() {
}

LinuxTunInterface::~LinuxTunInterface() {
    closeInterface();
}

bool LinuxTunInterface::openInterface(const std::string& interface_name) {
    if (isOpen()) {
        setLastError("Interface already open");
        return false;
    }
    
    // 打开TUN设备文件
    tun_fd_ = open("/dev/net/tun", O_RDWR);
    if (tun_fd_ < 0) {
        setLastError("Failed to open /dev/net/tun: " + std::string(strerror(errno)) + 
                    ". Make sure TUN module is loaded and you have root privileges.");
        return false;
    }
    
    // 配置TUN接口
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    // 设置接口类型为TUN
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // 设置接口名称
    if (!interface_name.empty()) {
        strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
        interface_name_ = interface_name;
    }
    
    // 创建TUN接口
    if (ioctl(tun_fd_, TUNSETIFF, &ifr) < 0) {
        setLastError("Failed to create TUN interface: " + std::string(strerror(errno)));
        close(tun_fd_);
        tun_fd_ = -1;
        return false;
    }
    
    // 获取实际的接口名称
    interface_name_ = ifr.ifr_name;
    
    // 设置非阻塞模式
    int flags = fcntl(tun_fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(tun_fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        setLastError("Failed to set non-blocking mode: " + std::string(strerror(errno)));
        closeInterface();
        return false;
    }
    
    std::cout << "TUN interface created: " << interface_name_ << std::endl;
    return true;
}

void LinuxTunInterface::closeInterface() {
    if (tun_fd_ >= 0) {
        // 先禁用接口
        setInterfaceStatus(false);
        
        close(tun_fd_);
        tun_fd_ = -1;
        interface_name_.clear();
        ip_address_.clear();
        netmask_.clear();
        interface_up_ = false;
        
        std::cout << "TUN interface closed" << std::endl;
    }
}

bool LinuxTunInterface::setIPAddress(const std::string& ip_address, const std::string& netmask) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    // 使用ip命令设置IP地址
    std::ostringstream cmd;
    int cidr = netmaskToCIDR(netmask);
    cmd << "ip addr add " << ip_address << "/" << cidr 
        << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    ip_address_ = ip_address;
    netmask_ = netmask;
    
    std::cout << "Set IP address: " << ip_address << "/" << cidr 
              << " on " << interface_name_ << std::endl;
    return true;
}

bool LinuxTunInterface::setInterfaceStatus(bool up) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    std::ostringstream cmd;
    cmd << "ip link set " << interface_name_ << (up ? " up" : " down");
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    interface_up_ = up;
    std::cout << "Interface " << interface_name_ << " is now " 
              << (up ? "up" : "down") << std::endl;
    return true;
}

bool LinuxTunInterface::addRoute(const std::string& destination, const std::string& netmask, const std::string& gateway) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    std::ostringstream cmd;
    int cidr = netmaskToCIDR(netmask);
    cmd << "ip route add " << destination << "/" << cidr;
    
    if (!gateway.empty()) {
        cmd << " via " << gateway;
    }
    
    cmd << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Added route: " << destination << "/" << cidr 
              << " via " << interface_name_ << std::endl;
    return true;
}

bool LinuxTunInterface::removeRoute(const std::string& destination, const std::string& netmask) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    std::ostringstream cmd;
    int cidr = netmaskToCIDR(netmask);
    cmd << "ip route del " << destination << "/" << cidr 
        << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Removed route: " << destination << "/" << cidr 
              << " from " << interface_name_ << std::endl;
    return true;
}

bool LinuxTunInterface::readPacket(uint8_t* buffer, size_t buffer_size, size_t* bytes_read) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    ssize_t result = read(tun_fd_, buffer, buffer_size);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 非阻塞模式下没有数据可读
            *bytes_read = 0;
            return true;
        }
        setLastError("Failed to read from TUN interface: " + std::string(strerror(errno)));
        return false;
    }
    
    *bytes_read = static_cast<size_t>(result);
    stats_.rx_packets++;
    stats_.rx_bytes += *bytes_read;
    
    return true;
}

bool LinuxTunInterface::writePacket(const uint8_t* data, size_t length, size_t* bytes_written) {
    if (!isOpen()) {
        setLastError("Interface not open");
        return false;
    }
    
    ssize_t result = write(tun_fd_, data, length);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 非阻塞模式下暂时无法写入
            *bytes_written = 0;
            return true;
        }
        setLastError("Failed to write to TUN interface: " + std::string(strerror(errno)));
        stats_.tx_errors++;
        return false;
    }
    
    *bytes_written = static_cast<size_t>(result);
    stats_.tx_packets++;
    stats_.tx_bytes += *bytes_written;
    
    return true;
}

LinuxTunInterface::InterfaceStats LinuxTunInterface::getStats() const {
    return stats_;
}

bool LinuxTunInterface::isTunModuleAvailable() {
    // 检查/dev/net/tun是否存在
    struct stat st;
    if (stat("/dev/net/tun", &st) != 0) {
        return false;
    }
    
    // 检查是否为字符设备
    return S_ISCHR(st.st_mode);
}

std::vector<std::string> LinuxTunInterface::getAvailableInterfaces() {
    std::vector<std::string> interfaces;
    
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                std::string name = ifa->ifa_name;
                if (name.substr(0, 3) == "tun") {
                    interfaces.push_back(name);
                }
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
    
    return interfaces;
}

bool LinuxTunInterface::hasRootPrivileges() {
    return geteuid() == 0;
}

bool LinuxTunInterface::executeCommand(const std::string& command) {
    int result = system(command.c_str());
    if (result != 0) {
        setLastError("Command failed: " + command + " (exit code: " + std::to_string(result) + ")");
        return false;
    }
    return true;
}

void LinuxTunInterface::setLastError(const std::string& error) {
    last_error_ = error;
    std::cerr << "[TUN] Error: " << error << std::endl;
}

uint32_t LinuxTunInterface::ipStringToInt(const std::string& ip) {
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 0) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

std::string LinuxTunInterface::ipIntToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}

int LinuxTunInterface::netmaskToCIDR(const std::string& netmask) {
    uint32_t mask = ipStringToInt(netmask);
    int cidr = 0;
    
    while (mask) {
        cidr += mask & 1;
        mask >>= 1;
    }
    
    return cidr;
}

// TunInterfaceManager实现

bool TunInterfaceManager::isTunModuleLoaded() {
    std::ifstream proc_modules("/proc/modules");
    std::string line;
    
    while (std::getline(proc_modules, line)) {
        if (line.find("tun ") == 0) {
            return true;
        }
    }
    
    return false;
}

bool TunInterfaceManager::loadTunModule() {
    if (isTunModuleLoaded()) {
        return true;
    }
    
    // 尝试加载TUN模块
    int result = system("modprobe tun");
    if (result != 0) {
        std::cerr << "Failed to load TUN module. Make sure you have root privileges." << std::endl;
        return false;
    }
    
    // 等待模块加载完成
    usleep(100000); // 100ms
    
    return isTunModuleLoaded();
}

std::vector<std::string> TunInterfaceManager::getSystemTunInterfaces() {
    std::vector<std::string> interfaces;
    
    std::ifstream proc_net_dev("/proc/net/dev");
    std::string line;
    
    // 跳过前两行（标题）
    std::getline(proc_net_dev, line);
    std::getline(proc_net_dev, line);
    
    while (std::getline(proc_net_dev, line)) {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string interface_name = line.substr(0, colon_pos);
            
            // 去除前后空格
            interface_name.erase(0, interface_name.find_first_not_of(" \t"));
            interface_name.erase(interface_name.find_last_not_of(" \t") + 1);
            
            if (interface_name.substr(0, 3) == "tun") {
                interfaces.push_back(interface_name);
            }
        }
    }
    
    return interfaces;
}

bool TunInterfaceManager::interfaceExists(const std::string& name) {
    auto interfaces = TunInterfaceManager::getSystemTunInterfaces();
    return std::find(interfaces.begin(), interfaces.end(), name) != interfaces.end();
}

std::string TunInterfaceManager::getInterfaceIP(const std::string& name) {
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) != 0) {
        return "";
    }
    
    std::string ip_address;
    for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
            std::string(ifa->ifa_name) == name) {
            
            struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            ip_address = inet_ntoa(sin->sin_addr);
            break;
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return ip_address;
}

bool TunInterfaceManager::getInterfaceStatus(const std::string& name) {
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) != 0) {
        return false;
    }
    
    bool is_up = false;
    for (struct ifaddrs* ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (std::string(ifa->ifa_name) == name) {
            is_up = (ifa->ifa_flags & IFF_UP) != 0;
            break;
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return is_up;
}

} // namespace client
} // namespace sduvpn
