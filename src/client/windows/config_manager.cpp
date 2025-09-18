#include "client/config_manager.h"
#include "client/windows_vpn_client.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <windows.h>
#include <shlobj.h>

namespace sduvpn {
namespace client {

ConfigManager::ConfigManager() {
}

ConfigManager::~ConfigManager() {
}

bool ConfigManager::initialize(const std::string& config_dir) {
    if (!config_dir.empty()) {
        config_dir_ = config_dir;
    } else {
        config_dir_ = getConfigDirectory();
    }
    
    return createConfigDirectory();
}

bool ConfigManager::saveProfile(const VPNConnectionProfile& profile) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (profile.name.empty() || profile.server_address.empty()) {
        return false;
    }
    
    try {
        std::string file_path = getConfigFilePath(profile.name);
        std::ofstream file(file_path);
        
        if (!file.is_open()) {
            return false;
        }
        
        std::string json = profileToJson(profile);
        file << json;
        file.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<VPNConnectionProfile> ConfigManager::loadAllProfiles() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    std::vector<VPNConnectionProfile> profiles;
    
    try {
        WIN32_FIND_DATAA find_data;
        std::string search_pattern = config_dir_ + "\\*.json";
        HANDLE find_handle = FindFirstFileA(search_pattern.c_str(), &find_data);
        
        if (find_handle != INVALID_HANDLE_VALUE) {
            do {
                std::string filename = find_data.cFileName;
                std::string file_path = config_dir_ + "\\" + filename;
                
                std::ifstream file(file_path);
                if (file.is_open()) {
                    std::string json((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
                    file.close();
                    
                    auto profile = profileFromJson(json);
                    if (profile) {
                        profiles.push_back(*profile);
                    }
                }
            } while (FindNextFileA(find_handle, &find_data));
            
            FindClose(find_handle);
        }
    } catch (...) {
        // 忽略错误，返回空列表
    }
    
    return profiles;
}

std::unique_ptr<VPNConnectionProfile> ConfigManager::loadProfile(const std::string& name) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    try {
        std::string file_path = getConfigFilePath(name);
        std::ifstream file(file_path);
        
        if (!file.is_open()) {
            return nullptr;
        }
        
        std::string json((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
        file.close();
        
        return profileFromJson(json);
    } catch (...) {
        return nullptr;
    }
}

bool ConfigManager::deleteProfile(const std::string& name) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    std::string file_path = getConfigFilePath(name);
    return DeleteFileA(file_path.c_str()) == TRUE;
}

std::vector<VPNConnectionProfile> ConfigManager::getRecentProfiles(size_t count) {
    auto all_profiles = loadAllProfiles();
    
    // 按最后连接时间排序
    std::sort(all_profiles.begin(), all_profiles.end(), 
              [](const VPNConnectionProfile& a, const VPNConnectionProfile& b) {
                  return a.last_connected > b.last_connected;
              });
    
    if (all_profiles.size() > count) {
        all_profiles.resize(count);
    }
    
    return all_profiles;
}

std::vector<VPNConnectionProfile> ConfigManager::getFavoriteProfiles() {
    auto all_profiles = loadAllProfiles();
    
    std::vector<VPNConnectionProfile> favorites;
    std::copy_if(all_profiles.begin(), all_profiles.end(), std::back_inserter(favorites),
                 [](const VPNConnectionProfile& profile) {
                     return profile.is_favorite;
                 });
    
    return favorites;
}

void ConfigManager::updateConnectionStats(const std::string& name, bool success) {
    auto profile = loadProfile(name);
    if (!profile) {
        return;
    }
    
    profile->connection_count++;
    if (success) {
        profile->last_connected = getCurrentTimeString();
    }
    
    saveProfile(*profile);
}

bool ConfigManager::setAutoConnect(const std::string& name) {
    // 首先取消所有其他配置的自动连接
    auto all_profiles = loadAllProfiles();
    for (auto& profile : all_profiles) {
        if (profile.auto_connect) {
            profile.auto_connect = false;
            saveProfile(profile);
        }
    }
    
    // 设置指定配置为自动连接
    auto profile = loadProfile(name);
    if (!profile) {
        return false;
    }
    
    profile->auto_connect = true;
    return saveProfile(*profile);
}

std::unique_ptr<VPNConnectionProfile> ConfigManager::getAutoConnectProfile() {
    auto all_profiles = loadAllProfiles();
    
    for (const auto& profile : all_profiles) {
        if (profile.auto_connect) {
            return std::make_unique<VPNConnectionProfile>(profile);
        }
    }
    
    return nullptr;
}

bool ConfigManager::profileExists(const std::string& name) {
    std::string file_path = getConfigFilePath(name);
    std::ifstream file(file_path);
    return file.good();
}

std::string ConfigManager::generateUniqueName(const std::string& base_name) {
    if (!profileExists(base_name)) {
        return base_name;
    }
    
    for (int i = 1; i <= 100; ++i) {
        std::string unique_name = base_name + "_" + std::to_string(i);
        if (!profileExists(unique_name)) {
            return unique_name;
        }
    }
    
    return base_name + "_" + getCurrentTimeString();
}

std::string ConfigManager::encryptPassword(const std::string& password) {
    // 简单的XOR加密（在生产环境中应使用更强的加密）
    std::string encrypted = password;
    for (size_t i = 0; i < encrypted.length(); ++i) {
        encrypted[i] ^= ENCRYPTION_KEY[i % strlen(ENCRYPTION_KEY)];
    }
    
    // 转换为十六进制
    std::ostringstream hex_stream;
    for (unsigned char c : encrypted) {
        hex_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    
    return hex_stream.str();
}

std::string ConfigManager::decryptPassword(const std::string& encrypted_password) {
    // 从十六进制转换
    std::string encrypted;
    for (size_t i = 0; i < encrypted_password.length(); i += 2) {
        std::string byte_str = encrypted_password.substr(i, 2);
        char byte = static_cast<char>(std::stoul(byte_str, nullptr, 16));
        encrypted.push_back(byte);
    }
    
    // XOR解密
    for (size_t i = 0; i < encrypted.length(); ++i) {
        encrypted[i] ^= ENCRYPTION_KEY[i % strlen(ENCRYPTION_KEY)];
    }
    
    return encrypted;
}

std::string ConfigManager::getConfigFilePath(const std::string& name) {
    return config_dir_ + "\\" + sanitizeFileName(name) + ".json";
}

std::string ConfigManager::getConfigDirectory() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path) == S_OK) {
        return std::string(path) + "\\SDUVPN";
    }
    return ".\\config";
}

bool ConfigManager::createConfigDirectory() {
    return CreateDirectoryA(config_dir_.c_str(), nullptr) == TRUE || 
           GetLastError() == ERROR_ALREADY_EXISTS;
}

std::string ConfigManager::profileToJson(const VPNConnectionProfile& profile) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << profile.name << "\",\n";
    json << "  \"server_address\": \"" << profile.server_address << "\",\n";
    json << "  \"server_port\": " << profile.server_port << ",\n";
    json << "  \"username\": \"" << profile.username << "\",\n";
    json << "  \"password\": \"" << encryptPassword(profile.password) << "\",\n";
    json << "  \"tap_adapter_name\": \"" << profile.tap_adapter_name << "\",\n";
    json << "  \"virtual_ip\": \"" << profile.virtual_ip << "\",\n";
    json << "  \"virtual_netmask\": \"" << profile.virtual_netmask << "\",\n";
    json << "  \"keepalive_interval\": " << profile.keepalive_interval << ",\n";
    json << "  \"connection_timeout\": " << profile.connection_timeout << ",\n";
    json << "  \"auto_reconnect\": " << (profile.auto_reconnect ? "true" : "false") << ",\n";
    json << "  \"max_reconnect_attempts\": " << profile.max_reconnect_attempts << ",\n";
    json << "  \"connection_count\": " << profile.connection_count << ",\n";
    json << "  \"last_connected\": \"" << profile.last_connected << "\",\n";
    json << "  \"created_time\": \"" << profile.created_time << "\",\n";
    json << "  \"is_favorite\": " << (profile.is_favorite ? "true" : "false") << ",\n";
    json << "  \"auto_connect\": " << (profile.auto_connect ? "true" : "false") << "\n";
    json << "}";
    return json.str();
}

std::unique_ptr<VPNConnectionProfile> ConfigManager::profileFromJson(const std::string& json) {
    auto profile = std::make_unique<VPNConnectionProfile>();
    
    // 简单的JSON解析（在生产环境中应使用专业的JSON库）
    try {
        auto getValue = [&json](const std::string& key) -> std::string {
            std::string search = "\"" + key + "\": \"";
            size_t start = json.find(search);
            if (start == std::string::npos) return "";
            
            start += search.length();
            size_t end = json.find("\"", start);
            if (end == std::string::npos) return "";
            
            return json.substr(start, end - start);
        };
        
        auto getIntValue = [&json](const std::string& key) -> uint32_t {
            std::string search = "\"" + key + "\": ";
            size_t start = json.find(search);
            if (start == std::string::npos) return 0;
            
            start += search.length();
            size_t end = json.find_first_of(",\n}", start);
            if (end == std::string::npos) return 0;
            
            std::string value_str = json.substr(start, end - start);
            return static_cast<uint32_t>(std::stoul(value_str));
        };
        
        auto getBoolValue = [&json](const std::string& key) -> bool {
            std::string search = "\"" + key + "\": ";
            size_t start = json.find(search);
            if (start == std::string::npos) return false;
            
            return json.find("true", start) < json.find("false", start);
        };
        
        profile->name = getValue("name");
        profile->server_address = getValue("server_address");
        profile->server_port = static_cast<uint16_t>(getIntValue("server_port"));
        profile->username = getValue("username");
        profile->password = decryptPassword(getValue("password"));
        profile->tap_adapter_name = getValue("tap_adapter_name");
        profile->virtual_ip = getValue("virtual_ip");
        profile->virtual_netmask = getValue("virtual_netmask");
        profile->keepalive_interval = getIntValue("keepalive_interval");
        profile->connection_timeout = getIntValue("connection_timeout");
        profile->auto_reconnect = getBoolValue("auto_reconnect");
        profile->max_reconnect_attempts = getIntValue("max_reconnect_attempts");
        profile->connection_count = getIntValue("connection_count");
        profile->last_connected = getValue("last_connected");
        profile->created_time = getValue("created_time");
        profile->is_favorite = getBoolValue("is_favorite");
        profile->auto_connect = getBoolValue("auto_connect");
        
        return profile;
    } catch (...) {
        return nullptr;
    }
}

std::string ConfigManager::getCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string ConfigManager::sanitizeFileName(const std::string& name) {
    std::string sanitized = name;
    
    // 替换不安全的文件名字符
    std::string unsafe_chars = "<>:\"/\\|?*";
    for (char c : unsafe_chars) {
        std::replace(sanitized.begin(), sanitized.end(), c, '_');
    }
    
    return sanitized;
}

std::unique_ptr<VPNConnectionProfile> ConfigManager::findProfileByLoginData(
    const std::string& server_address, 
    const std::string& username, 
    const std::string& password) {
    
    auto all_profiles = loadAllProfiles();
    
    for (const auto& profile : all_profiles) {
        if (profile.server_address == server_address && 
            profile.username == username && 
            profile.password == password) {
            return std::make_unique<VPNConnectionProfile>(profile);
        }
    }
    
    return nullptr;
}

// 配置辅助函数实现将在需要时添加

} // namespace client
} // namespace sduvpn
