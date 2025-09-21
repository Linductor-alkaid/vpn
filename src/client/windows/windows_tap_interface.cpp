#include "client/windows_tap_interface.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <winreg.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

namespace sduvpn {
namespace client {

WindowsTapInterface::WindowsTapInterface() 
    : tap_handle_(INVALID_HANDLE_VALUE) {
}

WindowsTapInterface::~WindowsTapInterface() {
    closeAdapter();
}

bool WindowsTapInterface::openAdapter(const std::string& adapter_name) {
    closeAdapter();
    
    // 查找TAP适配器
    auto adapters = findTapAdapters();
    if (adapters.empty()) {
        setLastError("No TAP adapters found. Please install TAP-Windows driver first.");
        return false;
    }
    
    // 如果指定了适配器名称，查找对应的GUID
    std::string target_guid;
    if (!adapter_name.empty()) {
        for (const auto& guid : adapters) {
            std::string name;
            if (getAdapterInfo(guid, name) && name == adapter_name) {
                target_guid = guid;
                break;
            }
        }
        if (target_guid.empty()) {
            setLastError("Specified TAP adapter not found: " + adapter_name);
            return false;
        }
    } else {
        // 使用第一个可用的适配器
        target_guid = adapters[0];
    }
    
    // 打开适配器
    if (!openAdapterByGuid(target_guid)) {
        return false;
    }
    
    adapter_guid_ = target_guid;
    getAdapterInfo(target_guid, adapter_name_);
    
    return true;
}

void WindowsTapInterface::closeAdapter() {
    if (tap_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(tap_handle_);
        tap_handle_ = INVALID_HANDLE_VALUE;
    }
    adapter_name_.clear();
    adapter_guid_.clear();
}

bool WindowsTapInterface::setIPAddress(const std::string& ip_address, 
                                     const std::string& subnet_mask,
                                     const std::string& gateway) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }
    
    // 构建netsh命令设置IP地址
    std::ostringstream cmd;
    cmd << "netsh interface ip set address \"" << adapter_name_ 
        << "\" static " << ip_address << " " << subnet_mask;
    
    if (!gateway.empty()) {
        cmd << " " << gateway;
    }
    
    return executeNetshCommand(cmd.str());
}

bool WindowsTapInterface::setAdapterStatus(bool connected) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }
    
    DWORD status = connected ? 1 : 0;
    DWORD bytes_returned;
    
    BOOL result = DeviceIoControl(
        tap_handle_,
        TAP_IOCTL_SET_MEDIA_STATUS,
        &status,
        sizeof(status),
        nullptr,
        0,
        &bytes_returned,
        nullptr
    );
    
    if (!result) {
        setLastError("Failed to set adapter media status: " + std::to_string(GetLastError()));
        return false;
    }
    
    return true;
}

bool WindowsTapInterface::readPacket(uint8_t* buffer, size_t buffer_size, DWORD* bytes_read) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }
    
    BOOL result = ReadFile(tap_handle_, buffer, static_cast<DWORD>(buffer_size), bytes_read, nullptr);
    
    if (result && *bytes_read > 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_received += *bytes_read;
        stats_.packets_received++;
    }
    
    if (!result) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            setLastError("Failed to read from TAP adapter: " + std::to_string(error));
            return false;
        }
    }
    
    return result;
}

bool WindowsTapInterface::writePacket(const uint8_t* buffer, size_t buffer_size, DWORD* bytes_written) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }
    
    BOOL result = WriteFile(tap_handle_, buffer, static_cast<DWORD>(buffer_size), bytes_written, nullptr);
    
    if (result && *bytes_written > 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_sent += *bytes_written;
        stats_.packets_sent++;
    }
    
    if (!result) {
        setLastError("Failed to write to TAP adapter: " + std::to_string(GetLastError()));
        return false;
    }
    
    return true;
}

bool WindowsTapInterface::addRoute(const std::string& destination, const std::string& netmask, const std::string& gateway) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }

    // 先删除可能存在的旧路由
    removeRoute(destination, netmask);
    
    // 获取TAP适配器的接口索引
    int ifIndex = getInterfaceIndex();
    if (ifIndex < 0) {
        setLastError("Failed to get interface index for " + adapter_name_);
        return false;
    }
    
    // 构建route add命令
    std::ostringstream cmd;
    cmd << "route add " << destination << " mask " << netmask;
    
    if (!gateway.empty()) {
        cmd << " " << gateway;
    } else {
        // 使用TAP适配器作为网关，通过接口索引指定
        cmd << " 0.0.0.0 if " << ifIndex;
    }
    
    cmd << " metric 1";
    
    std::string command = cmd.str();
    std::cout << "Executing: " << command << std::endl;
    
    int result = system(command.c_str());
    if (result != 0) {
        setLastError("Failed to add route: " + command);
        return false;
    }
    
    std::cout << "Added route: " << destination << " mask " << netmask 
              << " via " << adapter_name_ << " (if " << ifIndex << ")" << std::endl;
    return true;
}

bool WindowsTapInterface::removeRoute(const std::string& destination, const std::string& netmask) {
    if (!isOpen()) {
        setLastError("TAP adapter is not open");
        return false;
    }

    // 构建route delete命令
    std::ostringstream cmd;
    cmd << "route delete " << destination << " mask " << netmask;
    
    std::string command = cmd.str();
    std::cout << "Executing: " << command << std::endl;
    
    int result = system(command.c_str());
    if (result != 0) {
        setLastError("Failed to remove route: " + command);
        return false;
    }
    
    std::cout << "Removed route: " << destination << " mask " << netmask 
              << " from " << adapter_name_ << std::endl;
    return true;
}

int WindowsTapInterface::getInterfaceIndex() const {
    // 使用PowerShell命令获取TAP适配器的接口索引
    std::string command = "powershell -Command \"Get-NetAdapter | Where-Object {$_.Name -eq '" + adapter_name_ + "'} | Select-Object -ExpandProperty ifIndex\"";
    
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return -1;
    }
    
    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    
    // 解析结果
    try {
        return std::stoi(result);
    } catch (...) {
        return -1;
    }
}

WindowsTapInterface::Statistics WindowsTapInterface::getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<std::string> WindowsTapInterface::findTapAdapters() {
    std::vector<std::string> adapters;
    HKEY adapter_key;
    
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (result != ERROR_SUCCESS) {
        setLastError("Failed to open adapter registry key");
        return adapters;
    }
    
    char subkey_name[256];
    DWORD subkey_name_size;
    DWORD index = 0;
    
    while (true) {
        subkey_name_size = sizeof(subkey_name);
        result = RegEnumKeyExA(adapter_key, index++, subkey_name, &subkey_name_size, 
                              nullptr, nullptr, nullptr, nullptr);
        
        if (result != ERROR_SUCCESS) {
            break;
        }
        
        // 打开子键
        HKEY subkey;
        result = RegOpenKeyExA(adapter_key, subkey_name, 0, KEY_READ, &subkey);
        if (result != ERROR_SUCCESS) {
            continue;
        }
        
        // 检查ComponentId
        char component_id[256] = {0};
        DWORD component_id_size = sizeof(component_id);
        result = RegQueryValueExA(subkey, "ComponentId", nullptr, nullptr, 
                                 reinterpret_cast<LPBYTE>(component_id), &component_id_size);
        
        if (result == ERROR_SUCCESS && strcmp(component_id, TAP_COMPONENT_ID) == 0) {
            // 获取NetCfgInstanceId (GUID)
            char guid[256] = {0};
            DWORD guid_size = sizeof(guid);
            result = RegQueryValueExA(subkey, "NetCfgInstanceId", nullptr, nullptr, 
                                     reinterpret_cast<LPBYTE>(guid), &guid_size);
            
            if (result == ERROR_SUCCESS) {
                adapters.push_back(std::string(guid));
            }
        }
        
        RegCloseKey(subkey);
    }
    
    RegCloseKey(adapter_key);
    return adapters;
}

bool WindowsTapInterface::openAdapterByGuid(const std::string& guid) {
    std::string device_name = guidToDeviceName(guid);
    
    tap_handle_ = CreateFileA(
        device_name.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM,
        nullptr
    );
    
    if (tap_handle_ == INVALID_HANDLE_VALUE) {
        setLastError("Failed to open TAP adapter: " + std::to_string(GetLastError()));
        return false;
    }
    
    return true;
}

bool WindowsTapInterface::getAdapterInfo(const std::string& guid, std::string& name) {
    std::string key_path = std::string(NETWORK_CONNECTIONS_KEY) + "\\" + guid + "\\Connection";
    HKEY key;
    
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path.c_str(), 0, KEY_READ, &key);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    char adapter_name[256] = {0};
    DWORD name_size = sizeof(adapter_name);
    result = RegQueryValueExA(key, "Name", nullptr, nullptr, 
                             reinterpret_cast<LPBYTE>(adapter_name), &name_size);
    
    RegCloseKey(key);
    
    if (result == ERROR_SUCCESS) {
        name = std::string(adapter_name);
        return true;
    }
    
    return false;
}

std::string WindowsTapInterface::guidToDeviceName(const std::string& guid) {
    return "\\\\.\\Global\\" + guid + ".tap";
}

bool WindowsTapInterface::executeNetshCommand(const std::string& command) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // 创建进程执行netsh命令
    BOOL result = CreateProcessA(
        nullptr,
        const_cast<char*>(command.c_str()),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    
    if (!result) {
        setLastError("Failed to execute netsh command: " + std::to_string(GetLastError()));
        return false;
    }
    
    // 等待进程完成
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exit_code != 0) {
        setLastError("Netsh command failed with exit code: " + std::to_string(exit_code));
        return false;
    }
    
    return true;
}

void WindowsTapInterface::setLastError(const std::string& error) {
    last_error_ = error;
    std::cerr << "WindowsTapInterface Error: " << error << std::endl;
}

// TapAdapterManager implementation
std::vector<std::string> TapAdapterManager::getAvailableAdapters() {
    std::vector<std::string> adapters;
    HKEY adapter_key;
    
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WindowsTapInterface::ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (result != ERROR_SUCCESS) {
        return adapters;
    }
    
    char subkey_name[256];
    DWORD subkey_name_size;
    DWORD index = 0;
    
    while (true) {
        subkey_name_size = sizeof(subkey_name);
        result = RegEnumKeyExA(adapter_key, index++, subkey_name, &subkey_name_size, 
                              nullptr, nullptr, nullptr, nullptr);
        
        if (result != ERROR_SUCCESS) {
            break;
        }
        
        // 打开子键
        HKEY subkey;
        result = RegOpenKeyExA(adapter_key, subkey_name, 0, KEY_READ, &subkey);
        if (result != ERROR_SUCCESS) {
            continue;
        }
        
        // 检查ComponentId
        char component_id[256] = {0};
        DWORD component_id_size = sizeof(component_id);
        result = RegQueryValueExA(subkey, "ComponentId", nullptr, nullptr, 
                                 reinterpret_cast<LPBYTE>(component_id), &component_id_size);
        
        if (result == ERROR_SUCCESS && strcmp(component_id, WindowsTapInterface::TAP_COMPONENT_ID) == 0) {
            // 获取NetCfgInstanceId (GUID)
            char guid[256] = {0};
            DWORD guid_size = sizeof(guid);
            result = RegQueryValueExA(subkey, "NetCfgInstanceId", nullptr, nullptr, 
                                     reinterpret_cast<LPBYTE>(guid), &guid_size);
            
            if (result == ERROR_SUCCESS) {
                adapters.push_back(std::string(guid));
            }
        }
        
        RegCloseKey(subkey);
    }
    
    RegCloseKey(adapter_key);
    return adapters;
}

bool TapAdapterManager::isTapDriverInstalled() {
    auto adapters = getAvailableAdapters();
    return !adapters.empty();
}

std::string TapAdapterManager::getTapDriverVersion() {
    // 尝试从注册表获取驱动版本信息
    HKEY key;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                               "SOFTWARE\\TAP-Windows", 
                               0, KEY_READ, &key);
    
    if (result != ERROR_SUCCESS) {
        return "Unknown";
    }
    
    char version[256] = {0};
    DWORD version_size = sizeof(version);
    result = RegQueryValueExA(key, "Version", nullptr, nullptr, 
                             reinterpret_cast<LPBYTE>(version), &version_size);
    
    RegCloseKey(key);
    
    if (result == ERROR_SUCCESS) {
        return std::string(version);
    }
    
    return "Unknown";
}

bool TapAdapterManager::installTapDriver(const std::string& driver_path) {
    // 这里需要管理员权限执行驱动安装
    // 实际实现中应该调用适当的安装程序或使用设备管理API
    
    std::string command = "\"" + driver_path + "\" /S";
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    BOOL result = CreateProcessA(
        nullptr,
        const_cast<char*>(command.c_str()),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    
    if (!result) {
        return false;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exit_code == 0;
}

bool TapAdapterManager::uninstallTapDriver() {
    // 实现TAP驱动卸载逻辑
    // 这里需要管理员权限
    
    std::string command = "pnputil /delete-driver tap0901.inf /uninstall";
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    BOOL result = CreateProcessA(
        nullptr,
        const_cast<char*>(command.c_str()),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    
    if (!result) {
        return false;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exit_code == 0;
}

} // namespace client
} // namespace sduvpn
