#include "server/server_config.h"
#include <fstream>
#include <iostream>
#include <algorithm>

// 使用nlohmann/json库
#ifdef SDUVPN_USE_JSON
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#endif

namespace sduvpn {
namespace server {

ServerConfig::ServerConfig() {
    setDefaults();
}

void ServerConfig::setDefaults() {
    // 网络配置默认值
    listen_port_ = 1194;
    bind_address_ = "0.0.0.0";
    
    // 虚拟网络配置默认值
    virtual_network_ = "10.8.0.0";
    virtual_netmask_ = "255.255.255.0";
    tun_interface_name_ = "sduvpn0";
    
    // 客户端管理默认值
    max_clients_ = 100;
    client_timeout_seconds_ = 300; // 5分钟
    
    // 安全配置默认值
    server_certificate_ = "";
    server_private_key_ = "";
    ca_certificate_ = "";
    
    // 认证配置默认值
    require_authentication_ = true;
    users_.clear();
    
    // 日志配置默认值
    log_level_ = "info";
    log_file_ = "";
    log_to_console_ = true;
    
    // 性能配置默认值
    worker_threads_ = 4;
    receive_buffer_size_ = 65536;  // 64KB
    send_buffer_size_ = 65536;     // 64KB
    
    // 调试配置默认值
    debug_mode_ = false;
    enable_packet_dump_ = false;
}

#ifdef SDUVPN_USE_JSON
bool ServerConfig::loadFromFile(const std::string& config_file) {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        std::cerr << "无法打开配置文件: " << config_file << std::endl;
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    file.close();
    
    return loadFromString(content);
}

bool ServerConfig::loadFromString(const std::string& json_str) {
    try {
        json config = json::parse(json_str);
        
        // 网络配置
        if (config.contains("network")) {
            const auto& network = config["network"];
            if (network.contains("listen_port")) {
                listen_port_ = network["listen_port"].get<uint16_t>();
            }
            if (network.contains("bind_address")) {
                bind_address_ = network["bind_address"].get<std::string>();
            }
        }
        
        // 虚拟网络配置
        if (config.contains("virtual_network")) {
            const auto& vnet = config["virtual_network"];
            if (vnet.contains("network")) {
                virtual_network_ = vnet["network"].get<std::string>();
            }
            if (vnet.contains("netmask")) {
                virtual_netmask_ = vnet["netmask"].get<std::string>();
            }
            if (vnet.contains("interface_name")) {
                tun_interface_name_ = vnet["interface_name"].get<std::string>();
            }
        }
        
        // 客户端管理配置
        if (config.contains("clients")) {
            const auto& clients = config["clients"];
            if (clients.contains("max_clients")) {
                max_clients_ = clients["max_clients"].get<uint32_t>();
            }
            if (clients.contains("timeout_seconds")) {
                client_timeout_seconds_ = clients["timeout_seconds"].get<uint32_t>();
            }
        }
        
        // 安全配置
        if (config.contains("security")) {
            const auto& security = config["security"];
            if (security.contains("server_certificate")) {
                server_certificate_ = security["server_certificate"].get<std::string>();
            }
            if (security.contains("server_private_key")) {
                server_private_key_ = security["server_private_key"].get<std::string>();
            }
            if (security.contains("ca_certificate")) {
                ca_certificate_ = security["ca_certificate"].get<std::string>();
            }
        }
        
        // 认证配置
        if (config.contains("authentication")) {
            const auto& auth = config["authentication"];
            if (auth.contains("required")) {
                require_authentication_ = auth["required"].get<bool>();
            }
            if (auth.contains("users")) {
                users_.clear();
                for (const auto& user : auth["users"]) {
                    if (user.contains("username") && user.contains("password")) {
                        std::string username = user["username"].get<std::string>();
                        std::string password = user["password"].get<std::string>();
                        users_.emplace_back(username, password);
                    }
                }
            }
        }
        
        // 日志配置
        if (config.contains("logging")) {
            const auto& logging = config["logging"];
            if (logging.contains("level")) {
                log_level_ = logging["level"].get<std::string>();
            }
            if (logging.contains("file")) {
                log_file_ = logging["file"].get<std::string>();
            }
            if (logging.contains("console")) {
                log_to_console_ = logging["console"].get<bool>();
            }
        }
        
        // 性能配置
        if (config.contains("performance")) {
            const auto& perf = config["performance"];
            if (perf.contains("worker_threads")) {
                worker_threads_ = perf["worker_threads"].get<uint32_t>();
            }
            if (perf.contains("receive_buffer_size")) {
                receive_buffer_size_ = perf["receive_buffer_size"].get<uint32_t>();
            }
            if (perf.contains("send_buffer_size")) {
                send_buffer_size_ = perf["send_buffer_size"].get<uint32_t>();
            }
        }
        
        // 调试配置
        if (config.contains("debug")) {
            const auto& debug = config["debug"];
            if (debug.contains("debug_mode")) {
                debug_mode_ = debug["debug_mode"].get<bool>();
            }
            if (debug.contains("packet_dump")) {
                enable_packet_dump_ = debug["packet_dump"].get<bool>();
            }
        }
        
        return true;
        
    } catch (const json::exception& e) {
        std::cerr << "JSON解析错误: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "配置加载错误: " << e.what() << std::endl;
        return false;
    }
}

bool ServerConfig::saveToFile(const std::string& config_file) const {
    try {
        json config;
        
        // 网络配置
        config["network"]["listen_port"] = listen_port_;
        config["network"]["bind_address"] = bind_address_;
        
        // 虚拟网络配置
        config["virtual_network"]["network"] = virtual_network_;
        config["virtual_network"]["netmask"] = virtual_netmask_;
        config["virtual_network"]["interface_name"] = tun_interface_name_;
        
        // 客户端管理配置
        config["clients"]["max_clients"] = max_clients_;
        config["clients"]["timeout_seconds"] = client_timeout_seconds_;
        
        // 安全配置
        config["security"]["server_certificate"] = server_certificate_;
        config["security"]["server_private_key"] = server_private_key_;
        config["security"]["ca_certificate"] = ca_certificate_;
        
        // 认证配置
        config["authentication"]["required"] = require_authentication_;
        config["authentication"]["users"] = json::array();
        for (const auto& user : users_) {
            json user_obj;
            user_obj["username"] = user.first;
            user_obj["password"] = user.second;
            config["authentication"]["users"].push_back(user_obj);
        }
        
        // 日志配置
        config["logging"]["level"] = log_level_;
        config["logging"]["file"] = log_file_;
        config["logging"]["console"] = log_to_console_;
        
        // 性能配置
        config["performance"]["worker_threads"] = worker_threads_;
        config["performance"]["receive_buffer_size"] = receive_buffer_size_;
        config["performance"]["send_buffer_size"] = send_buffer_size_;
        
        // 调试配置
        config["debug"]["debug_mode"] = debug_mode_;
        config["debug"]["packet_dump"] = enable_packet_dump_;
        
        std::ofstream file(config_file);
        if (!file.is_open()) {
            std::cerr << "无法创建配置文件: " << config_file << std::endl;
            return false;
        }
        
        file << config.dump(4) << std::endl;
        file.close();
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "配置保存错误: " << e.what() << std::endl;
        return false;
    }
}
#else
// 不使用JSON库的简化实现
bool ServerConfig::loadFromFile(const std::string& config_file) {
    std::cout << "警告: 未启用JSON支持，使用默认配置" << std::endl;
    setDefaults();
    return true;
}

bool ServerConfig::loadFromString(const std::string& json_str) {
    std::cout << "警告: 未启用JSON支持，使用默认配置" << std::endl;
    setDefaults();
    return true;
}

bool ServerConfig::saveToFile(const std::string& config_file) const {
    std::cout << "警告: 未启用JSON支持，无法保存配置文件" << std::endl;
    return false;
}
#endif

bool ServerConfig::validate() const {
    // 验证端口范围
    if (listen_port_ == 0 || listen_port_ > 65535) {
        std::cerr << "无效的监听端口: " << listen_port_ << std::endl;
        return false;
    }
    
    // 验证最大客户端数
    if (max_clients_ == 0 || max_clients_ > 10000) {
        std::cerr << "无效的最大客户端数: " << max_clients_ << std::endl;
        return false;
    }
    
    // 验证超时时间
    if (client_timeout_seconds_ < 30 || client_timeout_seconds_ > 3600) {
        std::cerr << "无效的客户端超时时间: " << client_timeout_seconds_ << " 秒" << std::endl;
        return false;
    }
    
    // 验证工作线程数
    if (worker_threads_ == 0 || worker_threads_ > 64) {
        std::cerr << "无效的工作线程数: " << worker_threads_ << std::endl;
        return false;
    }
    
    // 验证缓冲区大小
    if (receive_buffer_size_ < 1024 || receive_buffer_size_ > 1048576) {
        std::cerr << "无效的接收缓冲区大小: " << receive_buffer_size_ << std::endl;
        return false;
    }
    
    if (send_buffer_size_ < 1024 || send_buffer_size_ > 1048576) {
        std::cerr << "无效的发送缓冲区大小: " << send_buffer_size_ << std::endl;
        return false;
    }
    
    // 验证虚拟网络配置（简单验证）
    if (virtual_network_.empty() || virtual_netmask_.empty()) {
        std::cerr << "虚拟网络配置不能为空" << std::endl;
        return false;
    }
    
    // 验证TUN接口名称
    if (tun_interface_name_.empty()) {
        std::cerr << "TUN接口名称不能为空" << std::endl;
        return false;
    }
    
    // 验证日志级别
    std::vector<std::string> valid_levels = {"trace", "debug", "info", "warn", "error", "critical"};
    if (std::find(valid_levels.begin(), valid_levels.end(), log_level_) == valid_levels.end()) {
        std::cerr << "无效的日志级别: " << log_level_ << std::endl;
        return false;
    }
    
    return true;
}

void ServerConfig::addUser(const std::string& username, const std::string& password) {
    // 检查用户是否已存在
    auto it = std::find_if(users_.begin(), users_.end(),
                          [&username](const std::pair<std::string, std::string>& user) {
                              return user.first == username;
                          });
    
    if (it != users_.end()) {
        // 更新现有用户密码
        it->second = password;
    } else {
        // 添加新用户
        users_.emplace_back(username, password);
    }
}

void ServerConfig::removeUser(const std::string& username) {
    users_.erase(std::remove_if(users_.begin(), users_.end(),
                               [&username](const std::pair<std::string, std::string>& user) {
                                   return user.first == username;
                               }),
                users_.end());
}

bool ServerConfig::verifyUser(const std::string& username, const std::string& password) const {
    auto it = std::find_if(users_.begin(), users_.end(),
                          [&username, &password](const std::pair<std::string, std::string>& user) {
                              return user.first == username && user.second == password;
                          });
    
    return it != users_.end();
}

} // namespace server
} // namespace sduvpn
