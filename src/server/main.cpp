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

// Signal handler function
void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", stopping server..." << std::endl;
    
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

// Monitor thread function
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
            // Calculate rates
            uint64_t bytes_sent_rate = (current_stats.bytes_sent - last_stats.bytes_sent) / interval_seconds;
            uint64_t bytes_recv_rate = (current_stats.bytes_received - last_stats.bytes_received) / interval_seconds;
            uint64_t packets_sent_rate = (current_stats.packets_sent - last_stats.packets_sent) / interval_seconds;
            uint64_t packets_recv_rate = (current_stats.packets_received - last_stats.packets_received) / interval_seconds;
            
            std::cout << "========================================" << std::endl;
            std::cout << "Server Statistics (Uptime: " << current_stats.uptime_seconds << " seconds)" << std::endl;
            std::cout << "Active Clients: " << current_stats.active_clients << std::endl;
            std::cout << "Total Sent: " << current_stats.bytes_sent << " bytes, " 
                      << current_stats.packets_sent << " packets" << std::endl;
            std::cout << "Total Received: " << current_stats.bytes_received << " bytes, " 
                      << current_stats.packets_received << " packets" << std::endl;
            std::cout << "Send Rate: " << bytes_sent_rate << " B/s, " 
                      << packets_sent_rate << " pps" << std::endl;
            std::cout << "Receive Rate: " << bytes_recv_rate << " B/s, " 
                      << packets_recv_rate << " pps" << std::endl;
            std::cout << "========================================" << std::endl;
        }
        
        last_time = current_time;
        last_stats = current_stats;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "SDUVPN Server v1.0.0" << std::endl;
    std::cout << "Copyright (C) 2024 SDUVPN Project" << std::endl;
    std::cout << std::endl;
    
    // Parse command line arguments
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
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                port = static_cast<uint16_t>(std::stoi(argv[++i]));
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-n" || arg == "--network") {
            if (i + 1 < argc) {
                network = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                interface_name = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-d" || arg == "--debug") {
            debug_mode = true;
        } else {
            std::cerr << "Error: Unknown argument " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Create server configuration
    ServerConfig config;
    
    // Load from configuration file
    if (!config_file.empty()) {
        std::cout << "Loading configuration from: " << config_file << std::endl;
        if (!config.loadFromFile(config_file)) {
            std::cerr << "Failed to load configuration file: " << config_file << std::endl;
            return 1;
        }
    }
    
    // Apply command line parameter overrides
    if (port != 0) {
        config.setListenPort(port);
    }
    
    if (!network.empty()) {
        // Parse network address and mask
        size_t slash_pos = network.find('/');
        if (slash_pos != std::string::npos) {
            std::string net_addr = network.substr(0, slash_pos);
            std::string net_mask = network.substr(slash_pos + 1);
            
            config.setVirtualNetwork(net_addr);
            
            // Convert CIDR to subnet mask
            if (net_mask.find('.') == std::string::npos) {
                // CIDR format (e.g., /24)
                int cidr = std::stoi(net_mask);
                uint32_t mask = 0xFFFFFFFF << (32 - cidr);
                
                struct in_addr addr;
                addr.s_addr = htonl(mask);
                config.setVirtualNetmask(inet_ntoa(addr));
            } else {
                // Dotted decimal format
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
    
    // Validate configuration
    if (!config.validate()) {
        std::cerr << "Configuration validation failed" << std::endl;
        return 1;
    }
    
    // Create server instance
    g_server = std::make_unique<VPNServer>();
    
    // Register signal handlers
    signal(SIGINT, signalHandler);   // Ctrl+C
    signal(SIGTERM, signalHandler);  // Termination signal
#ifndef _WIN32
    signal(SIGQUIT, signalHandler);  // Quit signal
    signal(SIGHUP, signalHandler);   // Hangup signal
#endif
    
    // Print server information
    printServerInfo(*g_server, config);
    
    // Start server
    if (!g_server->start(config)) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }
    
    // Start monitor thread
    std::thread monitor_thread(monitorThread, g_server.get());
    
    std::cout << "Server is running, press Ctrl+C to stop..." << std::endl;
    
    // Main loop
    while (g_server->isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Wait for monitor thread to finish
    if (monitor_thread.joinable()) {
        monitor_thread.join();
    }
    
    std::cout << "Server stopped" << std::endl;
    return 0;
}
