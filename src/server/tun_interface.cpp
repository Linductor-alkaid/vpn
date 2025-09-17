#include "server/tun_interface.h"
#include <iostream>
#include <cstring>
#include <sstream>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

namespace sduvpn {
namespace server {

TunTapInterface::TunTapInterface() 
    : fd_(-1)
    , is_tun_(true)
    , packet_callback_(nullptr) {
    std::memset(&stats_, 0, sizeof(stats_));
}

TunTapInterface::~TunTapInterface() {
    close();
}

bool TunTapInterface::createTun(const std::string& interface_name) {
    return createInterface(true, interface_name);
}

bool TunTapInterface::createTap(const std::string& interface_name) {
    return createInterface(false, interface_name);
}

#ifndef _WIN32
bool TunTapInterface::createInterface(bool is_tun, const std::string& interface_name) {
    // 打开TUN/TAP设备
    fd_ = open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        std::cerr << "Cannot open /dev/net/tun: " << strerror(errno) << std::endl;
        return false;
    }
    
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    
    // 设置接口类型
    ifr.ifr_flags = is_tun ? IFF_TUN : IFF_TAP;
    ifr.ifr_flags |= IFF_NO_PI;  // 不包含包信息头
    
    // 设置接口名称
    if (!interface_name.empty()) {
        strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }
    
    // 创建接口
    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        std::cerr << "TUNSETIFF ioctl failed: " << strerror(errno) << std::endl;
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    
    // 保存接口信息
    is_tun_ = is_tun;
    interface_name_ = ifr.ifr_name;
    
    std::cout << "Successfully created " << (is_tun_ ? "TUN" : "TAP") 
              << " interface: " << interface_name_ << std::endl;
    
    return true;
}
#else
bool TunTapInterface::createInterface(bool is_tun, const std::string& interface_name) {
    std::cerr << "TUN/TAP interface creation not supported on Windows platform" << std::endl;
    return false;
}
#endif

void TunTapInterface::close() {
    if (fd_ >= 0) {
#ifndef _WIN32
        ::close(fd_);
#endif
        fd_ = -1;
        interface_name_.clear();
        std::cout << "TUN/TAP interface closed" << std::endl;
    }
}

bool TunTapInterface::setIPAddress(const std::string& ip_address, const std::string& netmask) {
    if (!isOpen()) {
        std::cerr << "Interface not open" << std::endl;
        return false;
    }
    
    // Construct command to set IP address
    std::stringstream cmd;
    cmd << "ip addr add " << ip_address << "/" << netmask 
        << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    ip_address_ = ip_address;
    netmask_ = netmask;
    
    std::cout << "Set IP address: " << ip_address << "/" << netmask 
              << " to interface " << interface_name_ << std::endl;
    
    return true;
}

bool TunTapInterface::bringUp() {
    if (!isOpen()) {
        std::cerr << "Interface not open" << std::endl;
        return false;
    }
    
    std::stringstream cmd;
    cmd << "ip link set dev " << interface_name_ << " up";
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Interface " << interface_name_ << " is up" << std::endl;
    return true;
}

bool TunTapInterface::bringDown() {
    if (!isOpen()) {
        std::cerr << "Interface not open" << std::endl;
        return false;
    }
    
    std::stringstream cmd;
    cmd << "ip link set dev " << interface_name_ << " down";
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Interface " << interface_name_ << " is down" << std::endl;
    return true;
}

bool TunTapInterface::addRoute(const std::string& destination, 
                              const std::string& netmask,
                              const std::string& gateway) {
    if (!isOpen()) {
        std::cerr << "Interface not open" << std::endl;
        return false;
    }
    
    std::stringstream cmd;
    cmd << "ip route add " << destination << "/" << netmask;
    
    if (!gateway.empty()) {
        cmd << " via " << gateway;
    }
    
    cmd << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Add route: " << destination << "/" << netmask;
    if (!gateway.empty()) {
        std::cout << " via " << gateway;
    }
    std::cout << " dev " << interface_name_ << std::endl;
    
    return true;
}

bool TunTapInterface::removeRoute(const std::string& destination, const std::string& netmask) {
    if (!isOpen()) {
        std::cerr << "Interface not open" << std::endl;
        return false;
    }
    
    std::stringstream cmd;
    cmd << "ip route del " << destination << "/" << netmask 
        << " dev " << interface_name_;
    
    if (!executeCommand(cmd.str())) {
        return false;
    }
    
    std::cout << "Remove route: " << destination << "/" << netmask 
              << " dev " << interface_name_ << std::endl;
    
    return true;
}

int TunTapInterface::readPacket(uint8_t* buffer, size_t buffer_size) {
    if (!isOpen()) {
        return -1;
    }
    
#ifndef _WIN32
    ssize_t bytes_read = read(fd_, buffer, buffer_size);
    if (bytes_read > 0) {
        updateStats(bytes_read, 0);
        
        // 调用回调函数
        if (packet_callback_) {
            packet_callback_(buffer, bytes_read);
        }
    }
    
    return static_cast<int>(bytes_read);
#else
    return -1;
#endif
}

int TunTapInterface::writePacket(const uint8_t* data, size_t length) {
    if (!isOpen()) {
        return -1;
    }
    
#ifndef _WIN32
    ssize_t bytes_written = write(fd_, data, length);
    if (bytes_written > 0) {
        updateStats(0, bytes_written);
    }
    
    return static_cast<int>(bytes_written);
#else
    return -1;
#endif
}

bool TunTapInterface::setNonBlocking(bool non_blocking) {
    if (!isOpen()) {
        return false;
    }
    
#ifndef _WIN32
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Failed to get file flags: " << strerror(errno) << std::endl;
        return false;
    }
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    if (fcntl(fd_, F_SETFL, flags) < 0) {
        std::cerr << "Failed to set non-blocking mode: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
#else
    return false;
#endif
}

TunTapInterface::InterfaceStats TunTapInterface::getStats() const {
    return stats_;
}

void TunTapInterface::resetStats() {
    std::memset(&stats_, 0, sizeof(stats_));
}

bool TunTapInterface::executeCommand(const std::string& command) {
    std::cout << "Executing command: " << command << std::endl;
    
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Command execution failed: " << command << " (return code: " << result << ")" << std::endl;
        return false;
    }
    
    return true;
}

void TunTapInterface::updateStats(size_t rx_bytes, size_t tx_bytes) {
    if (rx_bytes > 0) {
        stats_.rx_packets++;
        stats_.rx_bytes += rx_bytes;
    }
    
    if (tx_bytes > 0) {
        stats_.tx_packets++;
        stats_.tx_bytes += tx_bytes;
    }
}

} // namespace server
} // namespace sduvpn
