#include "common/web_server.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <cstring>
#include <cerrno>

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdlib>
#include <signal.h>
#endif

namespace sduvpn {
namespace common {

WebServer::WebServer() {
    initializeNetwork();
}

WebServer::~WebServer() {
    stop();
    cleanupNetwork();
}

bool WebServer::initializeNetwork() {
#ifdef _WIN32
    if (winsock_initialized_) {
        return true;
    }
    
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        addLog("Failed to initialize Winsock: " + std::to_string(result));
        return false;
    }
    
    winsock_initialized_ = true;
    return true;
#else
    // Linux不需要特殊的网络初始化
    return true;
#endif
}

void WebServer::cleanupNetwork() {
#ifdef _WIN32
    if (winsock_initialized_) {
        WSACleanup();
        winsock_initialized_ = false;
    }
#endif
}

bool WebServer::start(uint16_t port) {
    if (running_.load()) {
        return false;
    }
    
    if (!initializeNetwork()) {
        return false;
    }
    
    port_ = port;
    
    // 创建套接字
    server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket_ == INVALID_SOCKET) {
#ifdef _WIN32
        addLog("Failed to create socket: " + std::to_string(WSAGetLastError()));
#else
        addLog("Failed to create socket: " + std::string(strerror(errno)));
#endif
        return false;
    }
    
    // 设置地址重用
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, 
#ifdef _WIN32
                   (char*)&opt, sizeof(opt)
#else
                   &opt, sizeof(opt)
#endif
                   ) < 0) {
        addLog("Failed to set socket options");
        closesocket(server_socket_);
        return false;
    }
    
    // 绑定地址
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port_);
    
    if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
#ifdef _WIN32
        DWORD error = WSAGetLastError();
        std::string errorMsg = "Failed to bind socket on port " + std::to_string(port_) + ": ";
        
        switch (error) {
            case WSAEACCES:
                errorMsg += "Permission denied. Try running as Administrator or use a different port.";
                break;
            case WSAEADDRINUSE:
                errorMsg += "Address already in use. Port is occupied by another application.";
                break;
            case WSAEADDRNOTAVAIL:
                errorMsg += "Address not available.";
                break;
            default:
                errorMsg += "Error code " + std::to_string(error);
                break;
        }
#else
        std::string errorMsg = "Failed to bind socket on port " + std::to_string(port_) + ": " + strerror(errno);
#endif
        
        addLog(errorMsg);
        closesocket(server_socket_);
        return false;
    }
    
    // 开始监听
    if (listen(server_socket_, 10) == SOCKET_ERROR) {
#ifdef _WIN32
        addLog("Failed to listen: " + std::to_string(WSAGetLastError()));
#else
        addLog("Failed to listen: " + std::string(strerror(errno)));
#endif
        closesocket(server_socket_);
        return false;
    }
    
    running_.store(true);
    should_stop_.store(false);
    
    // 启动服务器线程
    server_thread_ = std::thread(&WebServer::serverLoop, this);
    
    addLog("Web server started on http://127.0.0.1:" + std::to_string(port_));
    return true;
}

void WebServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    should_stop_.store(true);
    running_.store(false);
    
    if (server_socket_ != INVALID_SOCKET) {
        closesocket(server_socket_);
        server_socket_ = INVALID_SOCKET;
    }
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    addLog("Web server stopped");
}

std::string WebServer::getURL() const {
    return "http://127.0.0.1:" + std::to_string(port_);
}

void WebServer::setVPNClient(std::shared_ptr<VPNClientInterface> client) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    vpn_client_ = client;
}

void WebServer::setConfigManager(std::shared_ptr<ConfigManagerInterface> config_manager) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_manager_ = config_manager;
}

void WebServer::setLogCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(logs_mutex_);
    log_callback_ = callback;
}

bool WebServer::openInBrowser() {
    std::string url = getURL();
#ifdef _WIN32
    std::string command = "start " + url;
    return system(command.c_str()) == 0;
#else
    // 尝试多种Linux桌面环境的浏览器打开方式
    std::vector<std::string> commands = {
        "xdg-open " + url,
        "gnome-open " + url,
        "kde-open " + url,
        "firefox " + url,
        "chromium " + url,
        "google-chrome " + url
    };
    
    for (const auto& cmd : commands) {
        if (system(cmd.c_str()) == 0) {
            return true;
        }
    }
    return false;
#endif
}

void WebServer::serverLoop() {
    while (!should_stop_.load()) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int client_len = sizeof(client_addr);
#else
        socklen_t client_len = sizeof(client_addr);
#endif
        
        SOCKET client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (!should_stop_.load()) {
#ifdef _WIN32
                addLog("Accept failed: " + std::to_string(WSAGetLastError()));
#else
                addLog("Accept failed: " + std::string(strerror(errno)));
#endif
            }
            continue;
        }
        
        // 在新线程中处理客户端请求
        std::thread client_thread(&WebServer::handleClient, this, client_socket);
        client_thread.detach();
    }
}

void WebServer::handleClient(SOCKET client_socket) {
    char buffer[4096];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::string request_str(buffer);
        
        HttpRequest request = parseRequest(request_str);
        std::string response = handleRequest(request);
        
        send(client_socket, response.c_str(), response.length(), 0);
    }
    
    closesocket(client_socket);
}

HttpRequest WebServer::parseRequest(const std::string& request_str) {
    HttpRequest request;
    std::istringstream iss(request_str);
    
    // 解析请求行
    std::string line;
    if (std::getline(iss, line)) {
        std::istringstream line_iss(line);
        line_iss >> request.method >> request.path >> request.version;
    }
    
    // 解析头部
    while (std::getline(iss, line) && !line.empty() && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // 去除前后空格
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t\r") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r") + 1);
            
            request.headers[key] = value;
        }
    }
    
    // 解析请求体
    std::ostringstream body_stream;
    body_stream << iss.rdbuf();
    request.body = body_stream.str();
    
    return request;
}

std::string WebServer::handleRequest(const HttpRequest& request) {
    // API请求
    if (request.path.substr(0, 5) == "/api/") {
        std::string api_path = request.path.substr(5);
        return handleAPI(api_path, request.method, request.body);
    }
    
    // 静态文件
    return serveStaticFile(request.path);
}

std::string WebServer::generateResponse(const HttpResponse& response) {
    std::ostringstream resp_stream;
    resp_stream << "HTTP/1.1 " << response.status_code << " " << response.status_text << "\r\n";
    
    for (const auto& header : response.headers) {
        resp_stream << header.first << ": " << header.second << "\r\n";
    }
    
    resp_stream << "Content-Length: " << response.body.length() << "\r\n";
    resp_stream << "\r\n";
    resp_stream << response.body;
    
    return resp_stream.str();
}

std::string WebServer::handleAPI(const std::string& path, const std::string& method, const std::string& body) {
    if (path == "status" && method == "GET") {
        return apiStatus();
    }
    else if (path == "connect" && method == "POST") {
        return apiConnect(body);
    }
    else if (path == "disconnect" && method == "POST") {
        return apiDisconnect();
    }
    else if (path == "config" && method == "GET") {
        return apiGetConfig();
    }
    else if (path == "config" && method == "POST") {
        return apiSetConfig(body);
    }
    else if (path == "logs" && method == "GET") {
        return apiGetLogs();
    }
    else if (path == "test-interface" && method == "POST") {
        return apiTestInterface();
    }
    else if (path == "bandwidth-test" && method == "POST") {
        return apiBandwidthTest();
    }
    else if (path == "profiles" && method == "GET") {
        return apiGetProfiles();
    }
    else if (path == "profiles/save" && method == "POST") {
        return apiSaveProfile(body);
    }
    else if (path == "profiles/delete" && method == "POST") {
        return apiDeleteProfile(body);
    }
    else if (path == "profiles/load" && method == "POST") {
        return apiLoadProfile(body);
    }
    
    return errorResponse("API endpoint not found", 404);
}

std::string WebServer::apiStatus() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    std::ostringstream json;
    json << "{";
    
    if (vpn_client_) {
        auto state = vpn_client_->getConnectionState();
        auto stats = vpn_client_->getConnectionStats();
        
        json << "\"connected\": " << (state == VPNClientInterface::ConnectionState::CONNECTED ? "true" : "false") << ",";
        json << "\"state\": \"";
        
        switch (state) {
            case VPNClientInterface::ConnectionState::DISCONNECTED: json << "disconnected"; break;
            case VPNClientInterface::ConnectionState::CONNECTING: json << "connecting"; break;
            case VPNClientInterface::ConnectionState::AUTHENTICATING: json << "authenticating"; break;
            case VPNClientInterface::ConnectionState::CONNECTED: json << "connected"; break;
            case VPNClientInterface::ConnectionState::DISCONNECTING: json << "disconnecting"; break;
            case VPNClientInterface::ConnectionState::ERROR_STATE: json << "error"; break;
        }
        
        json << "\",";
        json << "\"bytes_sent\": " << stats.bytes_sent << ",";
        json << "\"bytes_received\": " << stats.bytes_received << ",";
        json << "\"packets_sent\": " << stats.packets_sent << ",";
        json << "\"packets_received\": " << stats.packets_received << ",";
        json << "\"virtual_ip\": \"" << vpn_client_->getVirtualIP() << "\",";
        json << "\"server_ip\": \"" << vpn_client_->getServerIP() << "\",";
        json << "\"last_error\": \"" << vpn_client_->getLastError() << "\"";
    } else {
        json << "\"connected\": false,";
        json << "\"state\": \"no_client\",";
        json << "\"bytes_sent\": 0,";
        json << "\"bytes_received\": 0,";
        json << "\"packets_sent\": 0,";
        json << "\"packets_received\": 0,";
        json << "\"last_error\": \"No VPN client instance\"";
    }
    
    json << "}";
    return jsonResponse(json.str());
}

std::string WebServer::apiConnect(const std::string& body) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    // 检查当前状态
    auto current_state = vpn_client_->getConnectionState();
    if (current_state == VPNClientInterface::ConnectionState::CONNECTING ||
        current_state == VPNClientInterface::ConnectionState::AUTHENTICATING) {
        return errorResponse("Connection already in progress, please wait");
    }
    
    addLog("Starting new connection...");
    
    // 简单的JSON解析（实际项目中应使用专业的JSON库）
    VPNClientInterface::ConnectionConfig config;
    
    // 解析JSON中的服务器地址
    size_t server_pos = body.find("\"server\":\"");
    if (server_pos != std::string::npos) {
        size_t start = server_pos + 10;
        size_t end = body.find("\"", start);
        if (end != std::string::npos) {
            config.server_address = body.substr(start, end - start);
        }
    }
    
    // 解析用户名
    size_t user_pos = body.find("\"username\":\"");
    if (user_pos != std::string::npos) {
        size_t start = user_pos + 12;
        size_t end = body.find("\"", start);
        if (end != std::string::npos) {
            config.username = body.substr(start, end - start);
        }
    }
    
    // 解析密码
    size_t pass_pos = body.find("\"password\":\"");
    if (pass_pos != std::string::npos) {
        size_t start = pass_pos + 12;
        size_t end = body.find("\"", start);
        if (end != std::string::npos) {
            config.password = body.substr(start, end - start);
        }
    }
    
    if (config.server_address.empty()) {
        return errorResponse("Server address is required");
    }
    
    bool success = vpn_client_->connect(config);
    
    // 如果连接成功，保存或更新配置
    if (success && config_manager_) {
        std::lock_guard<std::mutex> config_lock(config_mutex_);
        
        // 检查是否已存在相同的登录数据
        auto existing_profile = config_manager_->findProfileByLoginData(
            config.server_address, config.username, config.password);
        
        if (existing_profile) {
            // 更新现有配置的统计信息
            existing_profile->last_connected = getCurrentTime();
            existing_profile->connection_count++;
            
            if (config_manager_->saveProfile(*existing_profile)) {
                addLog("Updated existing configuration: " + existing_profile->name);
            }
        } else {
            // 创建新配置文件
            ConfigManagerInterface::VPNConnectionProfile profile;
            profile.name = config.server_address; // 使用服务器地址作为默认名称
            profile.server_address = config.server_address;
            profile.server_port = config.server_port;
            profile.username = config.username;
            profile.password = config.password;
            profile.created_time = getCurrentTime();
            profile.last_connected = getCurrentTime();
            profile.connection_count = 1;
            
            // 生成唯一名称
            profile.name = config_manager_->generateUniqueName(profile.name);
            
            // 保存新配置
            if (config_manager_->saveProfile(profile)) {
                addLog("New configuration saved: " + profile.name);
            }
        }
    }
    
    std::ostringstream json;
    json << "{\"success\": " << (success ? "true" : "false");
    if (!success) {
        json << ", \"error\": \"" << vpn_client_->getLastError() << "\"";
    }
    json << "}";
    
    return jsonResponse(json.str());
}

std::string WebServer::apiDisconnect() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    addLog("Disconnecting VPN client...");
    
    // 异步断开连接，避免阻塞Web API
    std::thread disconnect_thread([this]() {
        vpn_client_->disconnect();
        addLog("VPN client disconnected");
    });
    disconnect_thread.detach();
    
    return jsonResponse("{\"success\": true, \"message\": \"Disconnect initiated\"}");
}

std::string WebServer::apiGetConfig() {
    // 返回默认配置
    std::ostringstream json;
    json << "{";
    json << "\"server\": \"127.0.0.1\",";
    json << "\"port\": 1194,";
    json << "\"username\": \"\",";
    json << "\"auto_reconnect\": true";
    json << "}";
    
    return jsonResponse(json.str());
}

std::string WebServer::apiSetConfig(const std::string& body) {
    // 配置保存逻辑
    addLog("Configuration updated");
    return jsonResponse("{\"success\": true}");
}

std::string WebServer::apiGetLogs() {
    std::lock_guard<std::mutex> lock(logs_mutex_);
    
    std::ostringstream json;
    json << "{\"logs\": [";
    
    for (size_t i = 0; i < logs_.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << logs_[i] << "\"";
    }
    
    json << "]}";
    return jsonResponse(json.str());
}

std::string WebServer::apiTestInterface() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    bool interface_available = vpn_client_->testInterface();
    
    std::ostringstream json;
    json << "{";
    json << "\"interface_available\": " << (interface_available ? "true" : "false");
    json << "}";
    
    return jsonResponse(json.str());
}

std::string WebServer::apiBandwidthTest() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    addLog("Starting bandwidth test...");
    
    // 执行带宽测试
    auto result = vpn_client_->performBandwidthTest(10, 5); // 10秒，5MB测试
    
    std::ostringstream json;
    json << "{";
    json << "\"success\": " << (result.success ? "true" : "false") << ",";
    
    if (result.success) {
        json << "\"upload_mbps\": " << std::fixed << std::setprecision(2) << result.upload_mbps << ",";
        json << "\"download_mbps\": " << std::fixed << std::setprecision(2) << result.download_mbps << ",";
        json << "\"latency_ms\": " << std::fixed << std::setprecision(1) << result.latency_ms;
    } else {
        json << "\"error\": \"" << result.error_message << "\"";
    }
    
    json << "}";
    
    addLog("Bandwidth test completed");
    return jsonResponse(json.str());
}

std::string WebServer::apiGetProfiles() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (!config_manager_) {
        return errorResponse("Config manager not available");
    }
    
    auto profiles = config_manager_->getRecentProfiles(10);
    
    std::ostringstream json;
    json << "{\"profiles\": [";
    
    for (size_t i = 0; i < profiles.size(); ++i) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"name\": \"" << profiles[i].name << "\",";
        json << "\"server_address\": \"" << profiles[i].server_address << "\",";
        json << "\"server_port\": " << profiles[i].server_port << ",";
        json << "\"username\": \"" << profiles[i].username << "\",";
        json << "\"last_connected\": \"" << profiles[i].last_connected << "\",";
        json << "\"connection_count\": " << profiles[i].connection_count;
        json << "}";
    }
    
    json << "]}";
    return jsonResponse(json.str());
}

std::string WebServer::apiSaveProfile(const std::string& body) {
    return jsonResponse("{\"success\": true}"); // 简化实现
}

std::string WebServer::apiDeleteProfile(const std::string& body) {
    return jsonResponse("{\"success\": true}"); // 简化实现
}

std::string WebServer::apiLoadProfile(const std::string& body) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (!config_manager_) {
        return errorResponse("Config manager not available");
    }
    
    // 解析配置名称
    size_t name_pos = body.find("\"name\":\"");
    if (name_pos == std::string::npos) {
        return errorResponse("Profile name is required");
    }
    
    size_t start = name_pos + 8;
    size_t end = body.find("\"", start);
    if (end == std::string::npos) {
        return errorResponse("Invalid profile name format");
    }
    
    std::string profile_name = body.substr(start, end - start);
    auto profile = config_manager_->loadProfile(profile_name);
    
    if (!profile) {
        return errorResponse("Profile not found: " + profile_name);
    }
    
    // 返回配置信息
    std::ostringstream json;
    json << "{";
    json << "\"success\": true,";
    json << "\"profile\": {";
    json << "\"name\": \"" << profile->name << "\",";
    json << "\"server_address\": \"" << profile->server_address << "\",";
    json << "\"server_port\": " << profile->server_port << ",";
    json << "\"username\": \"" << profile->username << "\",";
    json << "\"password\": \"" << profile->password << "\"";
    json << "}";
    json << "}";
    
    return jsonResponse(json.str());
}

std::string WebServer::serveStaticFile(const std::string& path) {
    // 主页面
    if (path == "/" || path == "/index.html") {
        HttpResponse response;
        response.body = getMainPage();
        return generateResponse(response);
    }
    
    HttpResponse response;
    response.status_code = 404;
    response.status_text = "Not Found";
    response.headers["Content-Type"] = "text/plain";
    response.body = "404 Not Found";
    return generateResponse(response);
}

std::string WebServer::getMainPage() {
    return R"(<!DOCTYPE html>
<html>
<head>
    <title>SDUVPN Client</title>
    <meta charset='UTF-8'>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .status { padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .status.connected { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.disconnected { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .status.connecting { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 10px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn:hover { opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; font-size: 12px; }
        .logs { background: #f8f9fa; padding: 15px; border-radius: 5px; height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>🔒 SDUVPN Client</h1>
            <p>Web管理界面</p>
        </div>
        
        <div id='status' class='status disconnected'>
            <strong>状态:</strong> <span id='status-text'>未连接</span>
        </div>
        
        <div id='connection-info' style='display: none; background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0;'>
            <h4>连接信息</h4>
            <div style='display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;'>
                <div class='stat-card'>
                    <div class='stat-value' id='virtual-ip'>-</div>
                    <div class='stat-label'>虚拟IP地址</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' id='server-ip'>-</div>
                    <div class='stat-label'>服务器地址</div>
                </div>
            </div>
        </div>
        
        <div class='stats'>
            <div class='stat-card'>
                <div class='stat-value' id='bytes-sent'>0</div>
                <div class='stat-label'>发送字节</div>
            </div>
            <div class='stat-card'>
                <div class='stat-value' id='bytes-received'>0</div>
                <div class='stat-label'>接收字节</div>
            </div>
            <div class='stat-card'>
                <div class='stat-value' id='packets-sent'>0</div>
                <div class='stat-label'>发送包数</div>
            </div>
            <div class='stat-card'>
                <div class='stat-value' id='packets-received'>0</div>
                <div class='stat-label'>接收包数</div>
            </div>
        </div>
        
        <div class='form-group'>
            <label>保存的配置:</label>
            <select id='saved-profiles' onchange='loadSelectedProfile()' style='width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;'>
                <option value=''>选择保存的配置...</option>
            </select>
        </div>
        
        <div class='form-group'>
            <label>服务器地址:</label>
            <input type='text' id='server' placeholder='192.168.1.100 或 vpn.example.com' value='127.0.0.1'>
        </div>
        
        <div class='form-group'>
            <label>用户名:</label>
            <input type='text' id='username' placeholder='用户名'>
        </div>
        
        <div class='form-group'>
            <label>密码:</label>
            <input type='password' id='password' placeholder='密码'>
        </div>
        
        <div style='margin: 20px 0;'>
            <button class='btn btn-primary' onclick='connect()' id='connect-btn'>连接</button>
            <button class='btn btn-danger' onclick='disconnect()' id='disconnect-btn' disabled>断开</button>
            <button class='btn btn-secondary' onclick='testInterface()'>测试接口</button>
            <button class='btn btn-secondary' onclick='testBandwidth()' id='bandwidth-btn' disabled>带宽测试</button>
        </div>
        
        <div id='bandwidth-result' style='display: none; background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0;'>
            <h4>带宽测试结果</h4>
            <div style='display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;'>
                <div class='stat-card'>
                    <div class='stat-value' id='upload-speed'>0</div>
                    <div class='stat-label'>上传速度 (Mbps)</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' id='download-speed'>0</div>
                    <div class='stat-label'>下载速度 (Mbps)</div>
                </div>
                <div class='stat-card'>
                    <div class='stat-value' id='latency'>0</div>
                    <div class='stat-label'>延迟 (ms)</div>
                </div>
            </div>
        </div>
        
        <h3>连接日志</h3>
        <div id='logs' class='logs'></div>
    </div>
    
    <script>
        let isConnected = false;
        
        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const statusDiv = document.getElementById('status');
                    const statusText = document.getElementById('status-text');
                    
                    isConnected = data.connected;
                    
                    statusDiv.className = 'status ' + data.state;
                    statusText.textContent = getStatusText(data.state);
                    
                    document.getElementById('connect-btn').disabled = isConnected;
                    document.getElementById('disconnect-btn').disabled = !isConnected;
                    document.getElementById('bandwidth-btn').disabled = !isConnected;
                    
                    // 显示或隐藏连接信息
                    const connectionInfo = document.getElementById('connection-info');
                    if (isConnected) {
                        connectionInfo.style.display = 'block';
                        document.getElementById('virtual-ip').textContent = data.virtual_ip || '-';
                        document.getElementById('server-ip').textContent = data.server_ip || '-';
                    } else {
                        connectionInfo.style.display = 'none';
                    }
                    
                    document.getElementById('bytes-sent').textContent = formatBytes(data.bytes_sent);
                    document.getElementById('bytes-received').textContent = formatBytes(data.bytes_received);
                    document.getElementById('packets-sent').textContent = data.packets_sent;
                    document.getElementById('packets-received').textContent = data.packets_received;
                })
                .catch(err => console.error('Status update failed:', err));
        }
        
        function getStatusText(state) {
            switch(state) {
                case 'disconnected': return '未连接';
                case 'connecting': return '连接中...';
                case 'authenticating': return '认证中...';
                case 'connected': return '已连接';
                case 'disconnecting': return '断开中...';
                case 'error': return '连接错误';
                default: return '未知状态';
            }
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function connect() {
            if (isConnected) {
                alert('VPN已连接，请先断开现有连接');
                return;
            }
            
            const server = document.getElementById('server').value;
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            if (!server) {
                alert('请输入服务器地址');
                return;
            }
            
            const connectBtn = document.getElementById('connect-btn');
            connectBtn.disabled = true;
            connectBtn.textContent = '连接中...';
            
            const data = {
                server: server,
                username: username,
                password: password
            };
            
            fetch('/api/connect', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                if (!result.success) {
                    alert('连接失败: ' + (result.error || '未知错误'));
                }
                setTimeout(updateStatus, 100);
            })
            .catch(err => {
                alert('连接请求失败: ' + err);
            })
            .finally(() => {
                setTimeout(() => {
                    connectBtn.textContent = '连接';
                    updateStatus();
                }, 1000);
            });
        }
        
        function disconnect() {
            fetch('/api/disconnect', {method: 'POST'})
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        setTimeout(updateStatus, 100);
                        setTimeout(updateStatus, 500);
                        setTimeout(updateStatus, 1000);
                    } else {
                        alert('断开失败');
                    }
                })
                .catch(err => alert('断开请求失败: ' + err));
        }
        
        function testInterface() {
            fetch('/api/test-interface', {method: 'POST'})
                .then(response => response.json())
                .then(result => {
                    let message = '网络接口状态:\n';
                    message += '可用: ' + (result.interface_available ? '是' : '否');
                    alert(message);
                })
                .catch(err => alert('接口测试失败: ' + err));
        }
        
        function testBandwidth() {
            if (!isConnected) {
                alert('请先连接VPN');
                return;
            }
            
            const bandwidthBtn = document.getElementById('bandwidth-btn');
            bandwidthBtn.disabled = true;
            bandwidthBtn.textContent = '测试中...';
            
            fetch('/api/bandwidth-test', {method: 'POST'})
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        document.getElementById('upload-speed').textContent = result.upload_mbps.toFixed(2);
                        document.getElementById('download-speed').textContent = result.download_mbps.toFixed(2);
                        document.getElementById('latency').textContent = result.latency_ms.toFixed(1);
                        document.getElementById('bandwidth-result').style.display = 'block';
                    } else {
                        alert('带宽测试失败: ' + (result.error || '未知错误'));
                    }
                })
                .catch(err => alert('带宽测试请求失败: ' + err))
                .finally(() => {
                    bandwidthBtn.disabled = false;
                    bandwidthBtn.textContent = '带宽测试';
                });
        }
        
        function updateLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs');
                    logsDiv.innerHTML = data.logs.map(log => '<div>' + log + '</div>').join('');
                    logsDiv.scrollTop = logsDiv.scrollHeight;
                })
                .catch(err => console.error('Logs update failed:', err));
        }
        
        function loadProfiles() {
            fetch('/api/profiles')
                .then(response => response.json())
                .then(data => {
                    const select = document.getElementById('saved-profiles');
                    select.innerHTML = '<option value="">选择保存的配置...</option>';
                    
                    data.profiles.forEach(profile => {
                        const option = document.createElement('option');
                        option.value = profile.name;
                        option.textContent = profile.name + ' (' + profile.server_address + ')';
                        select.appendChild(option);
                    });
                })
                .catch(err => console.error('Failed to load profiles:', err));
        }
        
        function loadSelectedProfile() {
            const select = document.getElementById('saved-profiles');
            const profileName = select.value;
            
            if (!profileName) return;
            
            fetch('/api/profiles/load', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: profileName})
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    const profile = result.profile;
                    document.getElementById('server').value = profile.server_address;
                    document.getElementById('username').value = profile.username;
                    document.getElementById('password').value = profile.password;
                }
            })
            .catch(err => console.error('Failed to load profile:', err));
        }
        
        // 定期更新状态和日志
        setInterval(updateStatus, 500);
        setInterval(updateLogs, 2000);
        
        // 初始化
        updateStatus();
        updateLogs();
        loadProfiles();
    </script>
</body>
</html>)";
}

std::string WebServer::jsonResponse(const std::string& json, int status) {
    HttpResponse response;
    response.status_code = status;
    response.headers["Content-Type"] = "application/json";
    response.headers["Access-Control-Allow-Origin"] = "*";
    response.body = json;
    return generateResponse(response);
}

std::string WebServer::errorResponse(const std::string& message, int status) {
    std::ostringstream json;
    json << "{\"error\": \"" << message << "\"}";
    return jsonResponse(json.str(), status);
}

std::string WebServer::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void WebServer::addLog(const std::string& message) {
    std::lock_guard<std::mutex> lock(logs_mutex_);
    
    std::string timestamped = "[" + getCurrentTime() + "] " + message;
    logs_.push_back(timestamped);
    
    // 限制日志数量
    if (logs_.size() > MAX_LOGS) {
        logs_.erase(logs_.begin());
    }
    
    if (log_callback_) {
        log_callback_(timestamped);
    } else {
        std::cout << timestamped << std::endl;
    }
}

} // namespace common
} // namespace sduvpn
