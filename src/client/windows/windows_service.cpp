#include "client/windows_service.h"
#include "client/windows_vpn_client.h"
#include "common/web_server.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>

using namespace sduvpn::common;

namespace sduvpn {
namespace client {

// 静态成员初始化
WindowsServiceBase* WindowsServiceBase::instance_ = nullptr;

WindowsServiceBase::WindowsServiceBase(const std::string& service_name,
                                     const std::string& display_name,
                                     const std::string& description)
    : service_name_(service_name),
      display_name_(display_name),
      description_(description),
      status_handle_(nullptr) {
    
    // 初始化服务状态
    ZeroMemory(&service_status_, sizeof(service_status_));
    service_status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status_.dwCurrentState = SERVICE_STOPPED;
    service_status_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    
    instance_ = this;
}

bool WindowsServiceBase::installService(const std::string& executable_path) {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!sc_manager) {
        logEvent("Failed to open service control manager", EVENTLOG_ERROR_TYPE);
        return false;
    }
    
    SC_HANDLE service = CreateServiceA(
        sc_manager,
        service_name_.c_str(),
        display_name_.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        executable_path.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );
    
    bool success = (service != nullptr);
    
    if (success) {
        // 设置服务描述
        SERVICE_DESCRIPTIONA service_desc;
        service_desc.lpDescription = const_cast<char*>(description_.c_str());
        ChangeServiceConfig2A(service, SERVICE_CONFIG_DESCRIPTION, &service_desc);
        
        logEvent("Service installed successfully", EVENTLOG_INFORMATION_TYPE);
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            logEvent("Service already exists", EVENTLOG_WARNING_TYPE);
            success = true;
        } else {
            logEvent("Failed to install service: " + std::to_string(error), EVENTLOG_ERROR_TYPE);
        }
    }
    
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return success;
}

bool WindowsServiceBase::uninstallService() {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        logEvent("Failed to open service control manager", EVENTLOG_ERROR_TYPE);
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name_.c_str(), DELETE);
    if (!service) {
        logEvent("Failed to open service for deletion", EVENTLOG_ERROR_TYPE);
        CloseServiceHandle(sc_manager);
        return false;
    }
    
    bool success = DeleteService(service) == TRUE;
    
    if (success) {
        logEvent("Service uninstalled successfully", EVENTLOG_INFORMATION_TYPE);
    } else {
        logEvent("Failed to uninstall service: " + std::to_string(GetLastError()), EVENTLOG_ERROR_TYPE);
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return success;
}

bool WindowsServiceBase::startService() {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name_.c_str(), SERVICE_START);
    if (!service) {
        CloseServiceHandle(sc_manager);
        return false;
    }
    
    bool success = StartServiceA(service, 0, nullptr) == TRUE;
    
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return success;
}

bool WindowsServiceBase::stopService() {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name_.c_str(), SERVICE_STOP);
    if (!service) {
        CloseServiceHandle(sc_manager);
        return false;
    }
    
    SERVICE_STATUS status;
    bool success = ControlService(service, SERVICE_CONTROL_STOP, &status) == TRUE;
    
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return success;
}

bool WindowsServiceBase::isServiceInstalled() {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name_.c_str(), SERVICE_QUERY_STATUS);
    bool installed = (service != nullptr);
    
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return installed;
}

bool WindowsServiceBase::isServiceRunning() {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name_.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(sc_manager);
        return false;
    }
    
    SERVICE_STATUS status;
    bool success = QueryServiceStatus(service, &status) == TRUE;
    bool running = success && (status.dwCurrentState == SERVICE_RUNNING);
    
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return running;
}

void WINAPI WindowsServiceBase::serviceMain(DWORD argc, LPTSTR* argv) {
    if (!instance_) {
        return;
    }
    
    // 注册服务控制处理函数
    instance_->status_handle_ = RegisterServiceCtrlHandlerA(
        instance_->service_name_.c_str(),
        serviceControlHandler
    );
    
    if (!instance_->status_handle_) {
        return;
    }
    
    // 设置服务状态为启动挂起
    instance_->setServiceStatus(SERVICE_START_PENDING);
    
    // 调用子类的启动方法
    if (instance_->onStart()) {
        instance_->setServiceStatus(SERVICE_RUNNING);
        instance_->logEvent("Service started successfully", EVENTLOG_INFORMATION_TYPE);
    } else {
        instance_->setServiceStatus(SERVICE_STOPPED);
        instance_->logEvent("Service failed to start", EVENTLOG_ERROR_TYPE);
    }
}

void WINAPI WindowsServiceBase::serviceControlHandler(DWORD control) {
    if (!instance_) {
        return;
    }
    
    switch (control) {
        case SERVICE_CONTROL_STOP:
            instance_->setServiceStatus(SERVICE_STOP_PENDING);
            instance_->onStop();
            instance_->setServiceStatus(SERVICE_STOPPED);
            instance_->logEvent("Service stopped", EVENTLOG_INFORMATION_TYPE);
            break;
            
        case SERVICE_CONTROL_PAUSE:
            instance_->setServiceStatus(SERVICE_PAUSE_PENDING);
            instance_->onPause();
            instance_->setServiceStatus(SERVICE_PAUSED);
            instance_->logEvent("Service paused", EVENTLOG_INFORMATION_TYPE);
            break;
            
        case SERVICE_CONTROL_CONTINUE:
            instance_->setServiceStatus(SERVICE_CONTINUE_PENDING);
            instance_->onContinue();
            instance_->setServiceStatus(SERVICE_RUNNING);
            instance_->logEvent("Service continued", EVENTLOG_INFORMATION_TYPE);
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            // 返回当前状态
            break;
            
        default:
            break;
    }
}

void WindowsServiceBase::setServiceStatus(DWORD state) {
    updateServiceStatus(state);
}

void WindowsServiceBase::updateServiceStatus(DWORD state, DWORD exit_code, DWORD wait_hint) {
    service_status_.dwCurrentState = state;
    service_status_.dwWin32ExitCode = exit_code;
    service_status_.dwWaitHint = wait_hint;
    
    if (state == SERVICE_START_PENDING) {
        service_status_.dwControlsAccepted = 0;
    } else {
        service_status_.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    }
    
    if (status_handle_) {
        SetServiceStatus(status_handle_, &service_status_);
    }
}

void WindowsServiceBase::logEvent(const std::string& message, WORD type) {
    HANDLE event_source = RegisterEventSourceA(nullptr, service_name_.c_str());
    if (event_source) {
        const char* strings[] = { message.c_str() };
        ReportEventA(event_source, type, 0, 0, nullptr, 1, 0, strings, nullptr);
        DeregisterEventSource(event_source);
    }
    
    // 同时输出到控制台（调试时使用）
    std::cout << "[" << service_name_ << "] " << message << std::endl;
}

// SDUVPNWindowsService implementation
SDUVPNWindowsService::SDUVPNWindowsService()
    : WindowsServiceBase(SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_DESCRIPTION),
      vpn_client_(std::shared_ptr<common::VPNClientInterface>(WindowsVPNClientManager::getInstance().createClient().release())) {
    
    // 设置日志回调
    vpn_client_->setLogCallback([this](const std::string& message) {
        logEvent("VPN Client: " + message);
        
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (status_callback_) {
            status_callback_(message);
        }
    });
}

SDUVPNWindowsService::~SDUVPNWindowsService() {
    onStop();
}

void SDUVPNWindowsService::setConfigPath(const std::string& config_path) {
    config_path_ = config_path;
}

void SDUVPNWindowsService::setStatusCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    status_callback_ = callback;
}

bool SDUVPNWindowsService::onStart() {
    should_stop_.store(false);
    is_paused_.store(false);
    
    // 加载配置
    if (!loadConfiguration()) {
        logEvent("Failed to load configuration", EVENTLOG_ERROR_TYPE);
        return false;
    }
    
    // 启动服务线程
    service_thread_ = std::thread(&SDUVPNWindowsService::serviceThreadFunc, this);
    monitor_thread_ = std::thread(&SDUVPNWindowsService::monitorConnection, this);
    
    return true;
}

void SDUVPNWindowsService::onStop() {
    should_stop_.store(true);
    
    // 断开VPN连接
    if (vpn_client_) {
        vpn_client_->disconnect();
    }
    
    // 等待线程结束
    if (service_thread_.joinable()) {
        service_thread_.join();
    }
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void SDUVPNWindowsService::onPause() {
    is_paused_.store(true);
    
    // 暂停VPN连接（可选实现）
    if (vpn_client_) {
        vpn_client_->disconnect();
    }
}

void SDUVPNWindowsService::onContinue() {
    is_paused_.store(false);
    
    // 恢复VPN连接
    // 这里可以重新加载配置并连接
}

void SDUVPNWindowsService::serviceThreadFunc() {
    logEvent("Service thread started");
    
    while (!should_stop_.load()) {
        if (!is_paused_.load()) {
            // 检查VPN连接状态
            auto state = vpn_client_->getConnectionState();
            
            if (state == common::VPNClientInterface::ConnectionState::DISCONNECTED ||
                state == common::VPNClientInterface::ConnectionState::ERROR_STATE) {
                
                // 尝试重新连接
                logEvent("Attempting to reconnect VPN");
                
                // 这里需要重新加载配置并连接
                // 实际实现中应该从配置文件读取连接参数
                common::VPNClientInterface::ConnectionConfig config;
                config.server_address = "127.0.0.1"; // 示例配置
                config.server_port = 1194;
                config.username = "user";
                config.password = "pass";
                config.auto_reconnect = true;
                
                vpn_client_->connect(config);
            }
        }
        
        // 等待一段时间后再检查
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    
    logEvent("Service thread stopped");
}

bool SDUVPNWindowsService::loadConfiguration() {
    if (config_path_.empty()) {
        config_path_ = "sduvpn_client.conf";
    }
    
    std::ifstream config_file(config_path_);
    if (!config_file.is_open()) {
        logEvent("Configuration file not found: " + config_path_, EVENTLOG_WARNING_TYPE);
        return true; // 使用默认配置
    }
    
    // 这里应该实现配置文件解析
    // 暂时返回true表示使用默认配置
    logEvent("Configuration loaded from: " + config_path_);
    return true;
}

bool SDUVPNWindowsService::saveConfiguration() {
    if (config_path_.empty()) {
        return false;
    }
    
    std::ofstream config_file(config_path_);
    if (!config_file.is_open()) {
        return false;
    }
    
    // 这里应该实现配置文件保存
    // 暂时返回true
    return true;
}

void SDUVPNWindowsService::monitorConnection() {
    logEvent("Connection monitor started");
    
    while (!should_stop_.load()) {
        if (!is_paused_.load() && vpn_client_) {
            auto stats = vpn_client_->getConnectionStats();
            auto state = vpn_client_->getConnectionState();
            
            // 记录连接统计信息
            std::ostringstream oss;
            oss << "Connection Status: ";
            
            switch (state) {
                case common::VPNClientInterface::ConnectionState::DISCONNECTED:
                    oss << "DISCONNECTED";
                    break;
                case common::VPNClientInterface::ConnectionState::CONNECTING:
                    oss << "CONNECTING";
                    break;
                case common::VPNClientInterface::ConnectionState::AUTHENTICATING:
                    oss << "AUTHENTICATING";
                    break;
                case common::VPNClientInterface::ConnectionState::CONNECTED:
                    oss << "CONNECTED - Bytes Sent: " << stats.bytes_sent 
                        << ", Bytes Received: " << stats.bytes_received;
                    break;
                case common::VPNClientInterface::ConnectionState::DISCONNECTING:
                    oss << "DISCONNECTING";
                    break;
                case common::VPNClientInterface::ConnectionState::ERROR_STATE:
                    oss << "ERROR - " << vpn_client_->getLastError();
                    break;
            }
            
            logEvent(oss.str());
        }
        
        // 每30秒监控一次
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
    
    logEvent("Connection monitor stopped");
}

// ServiceManager implementation
bool ServiceManager::installSDUVPNService(const std::string& executable_path) {
    SDUVPNWindowsService service;
    return service.installService(executable_path);
}

bool ServiceManager::uninstallSDUVPNService() {
    SDUVPNWindowsService service;
    return service.uninstallService();
}

bool ServiceManager::startSDUVPNService() {
    SDUVPNWindowsService service;
    return service.startService();
}

bool ServiceManager::stopSDUVPNService() {
    SDUVPNWindowsService service;
    return service.stopService();
}

bool ServiceManager::restartSDUVPNService() {
    if (!stopSDUVPNService()) {
        return false;
    }
    
    // 等待服务完全停止
    if (!waitForServiceStatus(SDUVPNWindowsService::SERVICE_NAME, SERVICE_STOPPED)) {
        return false;
    }
    
    return startSDUVPNService();
}

std::string ServiceManager::getSDUVPNServiceStatus() {
    DWORD status = getServiceStatus(SDUVPNWindowsService::SERVICE_NAME);
    
    switch (status) {
        case SERVICE_STOPPED: return "STOPPED";
        case SERVICE_START_PENDING: return "START_PENDING";
        case SERVICE_STOP_PENDING: return "STOP_PENDING";
        case SERVICE_RUNNING: return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING: return "PAUSE_PENDING";
        case SERVICE_PAUSED: return "PAUSED";
        default: return "UNKNOWN";
    }
}

bool ServiceManager::serviceExists(const std::string& service_name) {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_QUERY_STATUS);
    bool exists = (service != nullptr);
    
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return exists;
}

DWORD ServiceManager::getServiceStatus(const std::string& service_name) {
    SC_HANDLE sc_manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!sc_manager) {
        return 0;
    }
    
    SC_HANDLE service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(sc_manager);
        return 0;
    }
    
    SERVICE_STATUS status;
    DWORD current_state = 0;
    
    if (QueryServiceStatus(service, &status)) {
        current_state = status.dwCurrentState;
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    
    return current_state;
}

bool ServiceManager::waitForServiceStatus(const std::string& service_name, 
                                        DWORD desired_status, 
                                        DWORD timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::milliseconds(timeout_ms);
    
    while (std::chrono::steady_clock::now() - start_time < timeout_duration) {
        DWORD current_status = getServiceStatus(service_name);
        if (current_status == desired_status) {
            return true;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return false;
}

} // namespace client
} // namespace sduvpn
