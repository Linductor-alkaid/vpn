#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <map>
#include <functional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace sduvpn {
namespace client {

// 前向声明
class WindowsVPNClient;
class ConfigManager;

/**
 * @brief 简单的HTTP Web服务器
 * 
 * 为VPN客户端提供Web管理界面
 */
class SimpleWebServer {
public:
    SimpleWebServer();
    ~SimpleWebServer();

    /**
     * @brief 启动Web服务器
     * @param port 监听端口
     * @return 是否启动成功
     */
    bool start(uint16_t port = 8080);

    /**
     * @brief 停止Web服务器
     */
    void stop();

    /**
     * @brief 检查服务器是否正在运行
     */
    bool isRunning() const { return running_.load(); }

    /**
     * @brief 获取服务器URL
     */
    std::string getURL() const;

    /**
     * @brief 设置VPN客户端实例
     */
    void setVPNClient(std::shared_ptr<WindowsVPNClient> client);

    /**
     * @brief 设置配置管理器
     */
    void setConfigManager(std::shared_ptr<ConfigManager> config_manager);

    /**
     * @brief 在浏览器中打开Web UI
     */
    bool openInBrowser();

private:
    // HTTP服务器
    void serverLoop();
    void handleClient(SOCKET client_socket);
    std::string handleRequest(const std::string& request);
    
    // API处理
    std::string handleAPI(const std::string& path, const std::string& method, const std::string& body);
    std::string apiStatus();
    std::string apiConnect(const std::string& body);
    std::string apiDisconnect();
    std::string apiGetConfig();
    std::string apiSetConfig(const std::string& body);
    std::string apiGetLogs();
    std::string apiTestTap();
    std::string apiBandwidthTest();
    std::string apiGetProfiles();
    std::string apiSaveProfile(const std::string& body);
    std::string apiDeleteProfile(const std::string& body);
    std::string apiLoadProfile(const std::string& body);
    
    // 静态文件服务
    std::string serveStaticFile(const std::string& path);
    std::string getContentType(const std::string& path);
    
    // 工具函数
    std::string jsonResponse(const std::string& json, int status = 200);
    std::string errorResponse(const std::string& message, int status = 400);
    std::string getCurrentTime();
    void addLog(const std::string& message);

private:
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};
    
    SOCKET server_socket_{INVALID_SOCKET};
    uint16_t port_{8080};
    std::thread server_thread_;
    
    // VPN客户端
    std::shared_ptr<WindowsVPNClient> vpn_client_;
    std::mutex client_mutex_;
    
    // 配置管理器
    std::shared_ptr<ConfigManager> config_manager_;
    std::mutex config_mutex_;
    
    // 日志系统
    std::vector<std::string> logs_;
    std::mutex logs_mutex_;
    static constexpr size_t MAX_LOGS = 500;
};

} // namespace client
} // namespace sduvpn
