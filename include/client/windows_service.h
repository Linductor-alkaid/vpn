#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

namespace sduvpn {
namespace client {

// 前向声明
class WindowsVPNClient;

/**
 * @brief Windows服务基类
 * 
 * 提供Windows服务的基础功能
 */
class WindowsServiceBase {
public:
    /**
     * @brief 构造函数
     * @param service_name 服务名称
     * @param display_name 服务显示名称
     * @param description 服务描述
     */
    WindowsServiceBase(const std::string& service_name,
                      const std::string& display_name,
                      const std::string& description);
    
    virtual ~WindowsServiceBase() = default;

    /**
     * @brief 安装服务
     * @param executable_path 可执行文件路径
     * @return 是否成功
     */
    bool installService(const std::string& executable_path);

    /**
     * @brief 卸载服务
     * @return 是否成功
     */
    bool uninstallService();

    /**
     * @brief 启动服务
     * @return 是否成功
     */
    bool startService();

    /**
     * @brief 停止服务
     * @return 是否成功
     */
    bool stopService();

    /**
     * @brief 检查服务是否已安装
     * @return 是否已安装
     */
    bool isServiceInstalled();

    /**
     * @brief 检查服务是否正在运行
     * @return 是否正在运行
     */
    bool isServiceRunning();

    /**
     * @brief 运行服务主循环
     * 由服务控制管理器调用
     */
    static void WINAPI serviceMain(DWORD argc, LPTSTR* argv);

    /**
     * @brief 服务控制处理函数
     * 处理服务控制请求
     */
    static void WINAPI serviceControlHandler(DWORD control);

    /**
     * @brief 获取服务名称
     * @return 服务名称
     */
    const std::string& getServiceName() const { return service_name_; }

protected:
    /**
     * @brief 服务启动时调用
     * 子类需要重写此方法
     */
    virtual bool onStart() = 0;

    /**
     * @brief 服务停止时调用
     * 子类需要重写此方法
     */
    virtual void onStop() = 0;

    /**
     * @brief 服务暂停时调用
     * 子类可以重写此方法
     */
    virtual void onPause() {}

    /**
     * @brief 服务继续时调用
     * 子类可以重写此方法
     */
    virtual void onContinue() {}

    /**
     * @brief 设置服务状态
     * @param state 服务状态
     */
    void setServiceStatus(DWORD state);

    /**
     * @brief 记录事件日志
     * @param message 日志消息
     * @param type 日志类型
     */
    void logEvent(const std::string& message, WORD type = EVENTLOG_INFORMATION_TYPE);

private:
    // 服务信息
    std::string service_name_;
    std::string display_name_;
    std::string description_;
    
    // 服务状态
    SERVICE_STATUS service_status_;
    SERVICE_STATUS_HANDLE status_handle_;
    
    // 静态实例指针（用于回调函数）
    static WindowsServiceBase* instance_;
    
    // 内部方法
    void updateServiceStatus(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0);
};

/**
 * @brief SDUVPN Windows服务实现
 */
class SDUVPNWindowsService : public WindowsServiceBase {
public:
    SDUVPNWindowsService();
    ~SDUVPNWindowsService() override;

    /**
     * @brief 设置配置文件路径
     * @param config_path 配置文件路径
     */
    void setConfigPath(const std::string& config_path);

    /**
     * @brief 设置状态回调函数
     * @param callback 状态回调函数
     */
    void setStatusCallback(std::function<void(const std::string&)> callback);

protected:
    bool onStart() override;
    void onStop() override;
    void onPause() override;
    void onContinue() override;

private:
    // 服务主循环
    void serviceThreadFunc();
    
    // 配置管理
    bool loadConfiguration();
    bool saveConfiguration();
    
    // 状态监控
    void monitorConnection();

public:
    // 服务常量 - 需要公开访问
    static constexpr const char* SERVICE_NAME = "SDUVPNClient";
    static constexpr const char* SERVICE_DISPLAY_NAME = "SDUVPN Client Service";
    static constexpr const char* SERVICE_DESCRIPTION = "SDUVPN Virtual Private Network Client Service";

private:
    std::unique_ptr<WindowsVPNClient> vpn_client_;
    std::string config_path_;
    std::atomic<bool> should_stop_{false};
    std::atomic<bool> is_paused_{false};
    std::thread service_thread_;
    std::thread monitor_thread_;
    
    // 回调函数
    std::function<void(const std::string&)> status_callback_;
    std::mutex callback_mutex_;
};

/**
 * @brief 服务管理器
 * 
 * 用于管理Windows服务的安装、卸载和控制
 */
class ServiceManager {
public:
    /**
     * @brief 安装SDUVPN服务
     * @param executable_path 可执行文件路径
     * @return 是否成功
     */
    static bool installSDUVPNService(const std::string& executable_path);

    /**
     * @brief 卸载SDUVPN服务
     * @return 是否成功
     */
    static bool uninstallSDUVPNService();

    /**
     * @brief 启动SDUVPN服务
     * @return 是否成功
     */
    static bool startSDUVPNService();

    /**
     * @brief 停止SDUVPN服务
     * @return 是否成功
     */
    static bool stopSDUVPNService();

    /**
     * @brief 重启SDUVPN服务
     * @return 是否成功
     */
    static bool restartSDUVPNService();

    /**
     * @brief 获取SDUVPN服务状态
     * @return 服务状态字符串
     */
    static std::string getSDUVPNServiceStatus();

    /**
     * @brief 检查服务是否存在
     * @param service_name 服务名称
     * @return 是否存在
     */
    static bool serviceExists(const std::string& service_name);

    /**
     * @brief 获取服务状态
     * @param service_name 服务名称
     * @return 服务状态
     */
    static DWORD getServiceStatus(const std::string& service_name);

    /**
     * @brief 等待服务状态改变
     * @param service_name 服务名称
     * @param desired_status 期望状态
     * @param timeout_ms 超时时间(毫秒)
     * @return 是否达到期望状态
     */
    static bool waitForServiceStatus(const std::string& service_name, 
                                   DWORD desired_status, 
                                   DWORD timeout_ms = 30000);
};

} // namespace client
} // namespace sduvpn
