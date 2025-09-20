#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <map>
#include <functional>
#include <queue>
#include <condition_variable>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

namespace sduvpn {
namespace common {

// 前向声明
class VPNClientInterface;
class ConfigManagerInterface;

/**
 * @brief HTTP请求结构
 */
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
};

/**
 * @brief HTTP响应结构
 */
struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::map<std::string, std::string> headers;
    std::string body;
    
    HttpResponse() {
        headers["Content-Type"] = "text/html";
        headers["Connection"] = "close";
    }
};

/**
 * @brief 通用Web服务器
 * 
 * 为VPN客户端提供跨平台的Web管理界面
 */
class WebServer {
public:
    WebServer();
    virtual ~WebServer();

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
    void setVPNClient(std::shared_ptr<VPNClientInterface> client);

    /**
     * @brief 设置配置管理器
     */
    void setConfigManager(std::shared_ptr<ConfigManagerInterface> config_manager);

    /**
     * @brief 在浏览器中打开Web UI
     */
    bool openInBrowser();

    /**
     * @brief 设置日志回调
     */
    void setLogCallback(std::function<void(const std::string&)> callback);

protected:
    // HTTP服务器
    void serverLoop();
    void handleClient(SOCKET client_socket);
    HttpRequest parseRequest(const std::string& request_str);
    std::string handleRequest(const HttpRequest& request);
    std::string generateResponse(const HttpResponse& response);
    
    // API处理
    std::string handleAPI(const std::string& path, const std::string& method, const std::string& body);
    std::string apiStatus();
    std::string apiConnect(const std::string& body);
    std::string apiDisconnect();
    std::string apiGetConfig();
    std::string apiSetConfig(const std::string& body);
    std::string apiGetLogs();
    std::string apiTestInterface();
    std::string apiBandwidthTest();
    std::string apiGetProfiles();
    std::string apiSaveProfile(const std::string& body);
    std::string apiDeleteProfile(const std::string& body);
    std::string apiLoadProfile(const std::string& body);
    
    // 静态文件服务
    std::string serveStaticFile(const std::string& path);
    std::string getMainPage();
    std::string getContentType(const std::string& path);
    
    // 工具函数
    std::string jsonResponse(const std::string& json, int status = 200);
    std::string errorResponse(const std::string& message, int status = 400);
    std::string getCurrentTime();
    void addLog(const std::string& message);

    // 平台相关的初始化和清理
    virtual bool initializeNetwork();
    virtual void cleanupNetwork();

private:
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};
    
    SOCKET server_socket_{INVALID_SOCKET};
    uint16_t port_{8080};
    std::thread server_thread_;
    
    // VPN客户端接口
    std::shared_ptr<VPNClientInterface> vpn_client_;
    std::mutex client_mutex_;
    
    // 配置管理器接口
    std::shared_ptr<ConfigManagerInterface> config_manager_;
    std::mutex config_mutex_;
    
    // 日志系统
    std::vector<std::string> logs_;
    std::mutex logs_mutex_;
    std::function<void(const std::string&)> log_callback_;
    static constexpr size_t MAX_LOGS = 500;

#ifdef _WIN32
    bool winsock_initialized_{false};
#endif
};

/**
 * @brief VPN客户端接口
 * 
 * 定义WebServer需要的VPN客户端功能
 */
class VPNClientInterface {
public:
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
        CONNECTED,
        DISCONNECTING,
        ERROR_STATE
    };

    struct ConnectionStats {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        std::chrono::steady_clock::time_point connection_start_time;
    };

    struct BandwidthTestResult {
        bool success = false;
        double upload_mbps = 0.0;
        double download_mbps = 0.0;
        double latency_ms = 0.0;
        std::string error_message;
    };

    struct ConnectionConfig {
        std::string server_address;
        uint16_t server_port = 1194;
        std::string username;
        std::string password;
        std::string interface_name;          // TAP适配器名称或TUN接口名称
        std::string virtual_ip = "10.8.0.2";
        std::string virtual_netmask = "255.255.255.0";
        uint32_t keepalive_interval = 30;
        uint32_t connection_timeout = 10;
        bool auto_reconnect = true;
        uint32_t max_reconnect_attempts = 5;
    };

    virtual ~VPNClientInterface() = default;

    virtual bool connect(const ConnectionConfig& config) = 0;
    virtual void disconnect() = 0;
    virtual ConnectionState getConnectionState() const = 0;
    virtual ConnectionStats getConnectionStats() const = 0;
    virtual std::string getLastError() const = 0;
    virtual BandwidthTestResult performBandwidthTest(uint32_t test_duration_seconds = 10, uint32_t test_size_mb = 5) = 0;
    virtual bool testInterface() = 0;  // 测试网络接口功能
};

/**
 * @brief 配置管理器接口
 */
class ConfigManagerInterface {
public:
    struct VPNConnectionProfile {
        std::string name;
        std::string server_address;
        uint16_t server_port = 1194;
        std::string username;
        std::string password;
        std::string interface_name;
        std::string virtual_ip;
        std::string virtual_netmask = "255.255.255.0";
        uint32_t keepalive_interval = 30;
        uint32_t connection_timeout = 10;
        bool auto_reconnect = true;
        uint32_t max_reconnect_attempts = 5;
        
        // 统计信息
        uint32_t connection_count = 0;
        std::string last_connected;
        std::string created_time;
        
        // 标记
        bool is_favorite = false;
        bool auto_connect = false;
    };

    virtual ~ConfigManagerInterface() = default;

    virtual bool initialize(const std::string& config_dir = "") = 0;
    virtual bool saveProfile(const VPNConnectionProfile& profile) = 0;
    virtual std::vector<VPNConnectionProfile> loadAllProfiles() = 0;
    virtual std::unique_ptr<VPNConnectionProfile> loadProfile(const std::string& name) = 0;
    virtual bool deleteProfile(const std::string& name) = 0;
    virtual std::vector<VPNConnectionProfile> getRecentProfiles(size_t count = 5) = 0;
    virtual std::vector<VPNConnectionProfile> getFavoriteProfiles() = 0;
    virtual void updateConnectionStats(const std::string& name, bool success) = 0;
    virtual bool setAutoConnect(const std::string& name) = 0;
    virtual std::unique_ptr<VPNConnectionProfile> getAutoConnectProfile() = 0;
    virtual bool profileExists(const std::string& name) = 0;
    virtual std::string generateUniqueName(const std::string& base_name) = 0;
    virtual std::unique_ptr<VPNConnectionProfile> findProfileByLoginData(
        const std::string& server_address, 
        const std::string& username, 
        const std::string& password) = 0;
};

} // namespace common
} // namespace sduvpn
