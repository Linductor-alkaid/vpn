#include "server/vpn_server.h"
#include "server/server_config.h"
#include <iostream>
#include <csignal>
#include <memory>
#include <thread>
#include <chrono>

using namespace sduvpn::server;

// 全局服务器实例
std::unique_ptr<VPNServer> g_server;

// 信号处理函数
void signalHandler(int signal) {
    std::cout << "\n收到信号 " << signal << "，正在停止服务器..." << std::endl;
    
    if (g_server) {
        g_server->stop();
    }
    
    exit(0);
}

// Print usage help
void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config FILE    Specify configuration file path" << std::endl;
    std::cout << "  -p, --port PORT      Specify listen port (default: 1194)" << std::endl;
    std::cout << "  -n, --network CIDR   Specify virtual network (default: 10.8.0.0/24)" << std::endl;
    std::cout << "  -i, --interface NAME Specify TUN interface name (default: sduvpn0)" << std::endl;
    std::cout << "  -d, --debug          Enable debug mode" << std::endl;
    std::cout << "  -h, --help           Show this help information" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " -c /etc/sduvpn/server.json" << std::endl;
    std::cout << "  " << program_name << " -p 1194 -n 10.8.0.0/24 -d" << std::endl;
}

// Print server information
void printServerInfo(const VPNServer& server, const ServerConfig& config) {
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "         SDUVPN Server Information" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Status: " << (server.isRunning() ? "Running" : "Stopped") << std::endl;
    std::cout << "Listen Port: " << config.getListenPort() << std::endl;
    std::cout << "Bind Address: " << config.getBindAddress() << std::endl;
    std::cout << "Virtual Network: " << config.getVirtualNetwork() << "/" << config.getVirtualNetmask() << std::endl;
    std::cout << "TUN Interface: " << config.getTunInterfaceName() << std::endl;
    std::cout << "Max Clients: " << config.getMaxClients() << std::endl;
    std::cout << "Client Timeout: " << config.getClientTimeoutSeconds() << " seconds" << std::endl;
    std::cout << "Worker Threads: " << config.getWorkerThreads() << std::endl;
    std::cout << "Debug Mode: " << (config.isDebugMode() ? "Enabled" : "Disabled") << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
}

// 监控线程函数
void monitorThread(VPNServer* server) {
    auto last_time = std::chrono::steady_clock::now();
    VPNServer::Statistics last_stats = server->getStatistics();
    
    while (server->isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (!server->isRunning()) {
            break;
        }
        
        auto current_time = std::chrono::steady_clock::now();
        VPNServer::Statistics current_stats = server->getStatistics();
        
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_time);
        double interval_seconds = duration.count();
        
        if (interval_seconds > 0) {
            // 计算速率
            uint64_t bytes_sent_rate = (current_stats.bytes_sent - last_stats.bytes_sent) / interval_seconds;
            uint64_t bytes_recv_rate = (current_stats.bytes_received - last_stats.bytes_received) / interval_seconds;
            uint64_t packets_sent_rate = (current_stats.packets_sent - last_stats.packets_sent) / interval_seconds;
            uint64_t packets_recv_rate = (current_stats.packets_received - last_stats.packets_received) / interval_seconds;
            
            std::cout << "========================================" << std::endl;
            std::cout << "服务器统计信息 (运行时间: " << current_stats.uptime_seconds << " 秒)" << std::endl;
            std::cout << "活跃客户端: " << current_stats.active_clients << std::endl;
            std::cout << "总发送: " << current_stats.bytes_sent << " 字节, " 
                      << current_stats.packets_sent << " 包" << std::endl;
            std::cout << "总接收: " << current_stats.bytes_received << " 字节, " 
                      << current_stats.packets_received << " 包" << std::endl;
            std::cout << "发送速率: " << bytes_sent_rate << " B/s, " 
                      << packets_sent_rate << " pps" << std::endl;
            std::cout << "接收速率: " << bytes_recv_rate << " B/s, " 
                      << packets_recv_rate << " pps" << std::endl;
            std::cout << "========================================" << std::endl;
        }
        
        last_time = current_time;
        last_stats = current_stats;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "SDUVPN 服务器 v1.0.0" << std::endl;
    std::cout << "版权所有 (C) 2024 SDUVPN 项目" << std::endl;
    std::cout << std::endl;
    
    // 解析命令行参数
    std::string config_file;
    uint16_t port = 0;
    std::string network;
    std::string interface_name;
    bool debug_mode = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "错误: " << arg << " 需要一个参数" << std::endl;
                return 1;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else {
                std::cerr << "错误: " << arg << " 需要一个参数" << std::endl;
                return 1;
            }
        } else if (arg == "-n" || arg == "--network") {
            if (i + 1 < argc) {
                network = argv[++i];
            } else {
                std::cerr << "错误: " << arg << " 需要一个参数" << std::endl;
                return 1;
            }
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                interface_name = argv[++i];
            } else {
                std::cerr << "错误: " << arg << " 需要一个参数" << std::endl;
                return 1;
            }
        } else if (arg == "-d" || arg == "--debug") {
            debug_mode = true;
        } else {
            std::cerr << "错误: 未知参数 " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // 创建服务器配置
    ServerConfig config;
    
    // 从配置文件加载
    if (!config_file.empty()) {
        std::cout << "从配置文件加载: " << config_file << std::endl;
        if (!config.loadFromFile(config_file)) {
            std::cerr << "无法加载配置文件: " << config_file << std::endl;
            return 1;
        }
    }
    
    // 应用命令行参数覆盖
    if (port != 0) {
        config.setListenPort(port);
    }
    
    if (!network.empty()) {
        // 解析网络地址和掩码
        size_t slash_pos = network.find('/');
        if (slash_pos != std::string::npos) {
            std::string net_addr = network.substr(0, slash_pos);
            std::string net_mask = network.substr(slash_pos + 1);
            
            config.setVirtualNetwork(net_addr);
            
            // 将CIDR转换为子网掩码
            if (net_mask.find('.') == std::string::npos) {
                // CIDR格式 (如 /24)
                int cidr = std::stoi(net_mask);
                uint32_t mask = 0xFFFFFFFF << (32 - cidr);
                
                struct in_addr addr;
                addr.s_addr = htonl(mask);
                config.setVirtualNetmask(inet_ntoa(addr));
            } else {
                // 点分十进制格式
                config.setVirtualNetmask(net_mask);
            }
        }
    }
    
    if (!interface_name.empty()) {
        config.setTunInterfaceName(interface_name);
    }
    
    if (debug_mode) {
        config.setDebugMode(true);
    }
    
    // 验证配置
    if (!config.validate()) {
        std::cerr << "配置验证失败" << std::endl;
        return 1;
    }
    
    // 创建服务器实例
    g_server = std::make_unique<VPNServer>();
    
    // 注册信号处理器
    signal(SIGINT, signalHandler);   // Ctrl+C
    signal(SIGTERM, signalHandler);  // 终止信号
#ifndef _WIN32
    signal(SIGQUIT, signalHandler);  // Quit信号
    signal(SIGHUP, signalHandler);   // Hangup信号
#endif
    
    // 打印服务器信息
    printServerInfo(*g_server, config);
    
    // 启动服务器
    if (!g_server->start(config)) {
        std::cerr << "服务器启动失败" << std::endl;
        return 1;
    }
    
    // 启动监控线程
    std::thread monitor_thread(monitorThread, g_server.get());
    
    std::cout << "服务器正在运行，按 Ctrl+C 停止..." << std::endl;
    
    // 主循环
    while (g_server->isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // 等待监控线程结束
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
    
    std::cout << "服务器已停止" << std::endl;
    return 0;
}
