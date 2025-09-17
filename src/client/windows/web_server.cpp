#include "client/web_server.h"
#include "client/windows_vpn_client.h"
#include "client/windows_tap_interface.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace sduvpn {
namespace client {

SimpleWebServer::SimpleWebServer() {
    // 初始化Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

SimpleWebServer::~SimpleWebServer() {
    stop();
    WSACleanup();
}

bool SimpleWebServer::start(uint16_t port) {
    if (running_.load()) {
        return false;
    }
    
    port_ = port;
    
    // 创建套接字
    server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket_ == INVALID_SOCKET) {
        addLog("Failed to create socket: " + std::to_string(WSAGetLastError()));
        return false;
    }
    
    // 设置地址重用
    int opt = 1;
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    // 绑定地址
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(port_);
    
    if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        DWORD error = WSAGetLastError();
        std::string errorMsg = "Failed to bind socket on port " + std::to_string(port_) + ": ";
        
        switch (error) {
            case WSAEACCES:
                errorMsg += "Permission denied (10013). Try running as Administrator or use a different port.";
                break;
            case WSAEADDRINUSE:
                errorMsg += "Address already in use (10048). Port is occupied by another application.";
                break;
            case WSAEADDRNOTAVAIL:
                errorMsg += "Address not available (10049).";
                break;
            default:
                errorMsg += "Error code " + std::to_string(error);
                break;
        }
        
        addLog(errorMsg);
        closesocket(server_socket_);
        return false;
    }
    
    // 开始监听
    if (listen(server_socket_, 10) == SOCKET_ERROR) {
        addLog("Failed to listen: " + std::to_string(WSAGetLastError()));
        closesocket(server_socket_);
        return false;
    }
    
    running_.store(true);
    should_stop_.store(false);
    
    // 启动服务器线程
    server_thread_ = std::thread(&SimpleWebServer::serverLoop, this);
    
    addLog("Web server started on http://127.0.0.1:" + std::to_string(port_));
    return true;
}

void SimpleWebServer::stop() {
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

std::string SimpleWebServer::getURL() const {
    return "http://127.0.0.1:" + std::to_string(port_);
}

void SimpleWebServer::setVPNClient(std::shared_ptr<WindowsVPNClient> client) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    vpn_client_ = client;
}

bool SimpleWebServer::openInBrowser() {
    std::string url = getURL();
    std::string command = "start " + url;
    return system(command.c_str()) == 0;
}

void SimpleWebServer::serverLoop() {
    while (!should_stop_.load()) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (!should_stop_.load()) {
                addLog("Accept failed: " + std::to_string(WSAGetLastError()));
            }
            continue;
        }
        
        // 在新线程中处理客户端请求
        std::thread client_thread(&SimpleWebServer::handleClient, this, client_socket);
        client_thread.detach();
    }
}

void SimpleWebServer::handleClient(SOCKET client_socket) {
    char buffer[4096];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::string request(buffer);
        std::string response = handleRequest(request);
        
        send(client_socket, response.c_str(), response.length(), 0);
    }
    
    closesocket(client_socket);
}

std::string SimpleWebServer::handleRequest(const std::string& request) {
    std::istringstream iss(request);
    std::string method, path, version;
    iss >> method >> path >> version;
    
    // 提取请求体
    std::string body;
    size_t body_start = request.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        body = request.substr(body_start + 4);
    }
    
    // API请求
    if (path.substr(0, 5) == "/api/") {
        return handleAPI(path.substr(5), method, body);
    }
    
    // 静态文件
    return serveStaticFile(path);
}

std::string SimpleWebServer::handleAPI(const std::string& path, const std::string& method, const std::string& body) {
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
    else if (path == "test-tap" && method == "POST") {
        return apiTestTap();
    }
    
    return errorResponse("API endpoint not found", 404);
}

std::string SimpleWebServer::apiStatus() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    std::ostringstream json;
    json << "{";
    
    if (vpn_client_) {
        auto state = vpn_client_->getConnectionState();
        auto stats = vpn_client_->getConnectionStats();
        
        json << "\"connected\": " << (state == WindowsVPNClient::ConnectionState::CONNECTED ? "true" : "false") << ",";
        json << "\"state\": \"";
        
        switch (state) {
            case WindowsVPNClient::ConnectionState::DISCONNECTED: json << "disconnected"; break;
            case WindowsVPNClient::ConnectionState::CONNECTING: json << "connecting"; break;
            case WindowsVPNClient::ConnectionState::AUTHENTICATING: json << "authenticating"; break;
            case WindowsVPNClient::ConnectionState::CONNECTED: json << "connected"; break;
            case WindowsVPNClient::ConnectionState::DISCONNECTING: json << "disconnecting"; break;
            case WindowsVPNClient::ConnectionState::ERROR_STATE: json << "error"; break;
        }
        
        json << "\",";
        json << "\"bytes_sent\": " << stats.bytes_sent << ",";
        json << "\"bytes_received\": " << stats.bytes_received << ",";
        json << "\"packets_sent\": " << stats.packets_sent << ",";
        json << "\"packets_received\": " << stats.packets_received << ",";
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

std::string SimpleWebServer::apiConnect(const std::string& body) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    // 简单的JSON解析（实际项目中应使用专业的JSON库）
    WindowsVPNClient::ConnectionConfig config;
    
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
    
    std::ostringstream json;
    json << "{\"success\": " << (success ? "true" : "false");
    if (!success) {
        json << ", \"error\": \"" << vpn_client_->getLastError() << "\"";
    }
    json << "}";
    
    return jsonResponse(json.str());
}

std::string SimpleWebServer::apiDisconnect() {
    std::lock_guard<std::mutex> lock(client_mutex_);
    
    if (!vpn_client_) {
        return errorResponse("No VPN client instance");
    }
    
    vpn_client_->disconnect();
    return jsonResponse("{\"success\": true}");
}

std::string SimpleWebServer::apiGetConfig() {
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

std::string SimpleWebServer::apiSetConfig(const std::string& body) {
    // 配置保存逻辑
    addLog("Configuration updated");
    return jsonResponse("{\"success\": true}");
}

std::string SimpleWebServer::apiGetLogs() {
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

std::string SimpleWebServer::apiTestTap() {
    bool tap_available = TapAdapterManager::isTapDriverInstalled();
    
    std::ostringstream json;
    json << "{";
    json << "\"tap_driver_installed\": " << (tap_available ? "true" : "false") << ",";
    json << "\"driver_version\": \"" << TapAdapterManager::getTapDriverVersion() << "\",";
    
    auto adapters = TapAdapterManager::getAvailableAdapters();
    json << "\"available_adapters\": " << adapters.size();
    json << "}";
    
    return jsonResponse(json.str());
}

std::string SimpleWebServer::serveStaticFile(const std::string& path) {
    // 主页面
    if (path == "/" || path == "/index.html") {
        return "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html\r\n"
               "Connection: close\r\n\r\n"
               "<!DOCTYPE html>\n"
               "<html>\n"
               "<head>\n"
               "    <title>SDUVPN Client</title>\n"
               "    <meta charset='UTF-8'>\n"
               "    <style>\n"
               "        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }\n"
               "        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n"
               "        .header { text-align: center; margin-bottom: 30px; }\n"
               "        .status { padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n"
               "        .status.connected { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }\n"
               "        .status.disconnected { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }\n"
               "        .status.connecting { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }\n"
               "        .form-group { margin-bottom: 15px; }\n"
               "        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }\n"
               "        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }\n"
               "        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 10px; }\n"
               "        .btn-primary { background: #007bff; color: white; }\n"
               "        .btn-danger { background: #dc3545; color: white; }\n"
               "        .btn-secondary { background: #6c757d; color: white; }\n"
               "        .btn:hover { opacity: 0.9; }\n"
               "        .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 20px 0; }\n"
               "        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }\n"
               "        .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }\n"
               "        .stat-label { color: #666; font-size: 12px; }\n"
               "        .logs { background: #f8f9fa; padding: 15px; border-radius: 5px; height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px; }\n"
               "    </style>\n"
               "</head>\n"
               "<body>\n"
               "    <div class='container'>\n"
               "        <div class='header'>\n"
               "            <h1>🔒 SDUVPN Client</h1>\n"
               "            <p>Web管理界面</p>\n"
               "        </div>\n"
               "        \n"
               "        <div id='status' class='status disconnected'>\n"
               "            <strong>状态:</strong> <span id='status-text'>未连接</span>\n"
               "        </div>\n"
               "        \n"
               "        <div class='stats'>\n"
               "            <div class='stat-card'>\n"
               "                <div class='stat-value' id='bytes-sent'>0</div>\n"
               "                <div class='stat-label'>发送字节</div>\n"
               "            </div>\n"
               "            <div class='stat-card'>\n"
               "                <div class='stat-value' id='bytes-received'>0</div>\n"
               "                <div class='stat-label'>接收字节</div>\n"
               "            </div>\n"
               "            <div class='stat-card'>\n"
               "                <div class='stat-value' id='packets-sent'>0</div>\n"
               "                <div class='stat-label'>发送包数</div>\n"
               "            </div>\n"
               "            <div class='stat-card'>\n"
               "                <div class='stat-value' id='packets-received'>0</div>\n"
               "                <div class='stat-label'>接收包数</div>\n"
               "            </div>\n"
               "        </div>\n"
               "        \n"
               "        <div class='form-group'>\n"
               "            <label>服务器地址:</label>\n"
               "            <input type='text' id='server' placeholder='192.168.1.100 或 vpn.example.com' value='127.0.0.1'>\n"
               "        </div>\n"
               "        \n"
               "        <div class='form-group'>\n"
               "            <label>用户名:</label>\n"
               "            <input type='text' id='username' placeholder='用户名'>\n"
               "        </div>\n"
               "        \n"
               "        <div class='form-group'>\n"
               "            <label>密码:</label>\n"
               "            <input type='password' id='password' placeholder='密码'>\n"
               "        </div>\n"
               "        \n"
               "        <div style='margin: 20px 0;'>\n"
               "            <button class='btn btn-primary' onclick='connect()' id='connect-btn'>连接</button>\n"
               "            <button class='btn btn-danger' onclick='disconnect()' id='disconnect-btn' disabled>断开</button>\n"
               "            <button class='btn btn-secondary' onclick='testTap()'>测试TAP</button>\n"
               "        </div>\n"
               "        \n"
               "        <h3>连接日志</h3>\n"
               "        <div id='logs' class='logs'></div>\n"
               "    </div>\n"
               "    \n"
               "    <script>\n"
               "        let isConnected = false;\n"
               "        \n"
               "        function updateStatus() {\n"
               "            fetch('/api/status')\n"
               "                .then(response => response.json())\n"
               "                .then(data => {\n"
               "                    const statusDiv = document.getElementById('status');\n"
               "                    const statusText = document.getElementById('status-text');\n"
               "                    \n"
               "                    isConnected = data.connected;\n"
               "                    \n"
               "                    statusDiv.className = 'status ' + data.state;\n"
               "                    statusText.textContent = getStatusText(data.state);\n"
               "                    \n"
               "                    document.getElementById('connect-btn').disabled = isConnected;\n"
               "                    document.getElementById('disconnect-btn').disabled = !isConnected;\n"
               "                    \n"
               "                    document.getElementById('bytes-sent').textContent = formatBytes(data.bytes_sent);\n"
               "                    document.getElementById('bytes-received').textContent = formatBytes(data.bytes_received);\n"
               "                    document.getElementById('packets-sent').textContent = data.packets_sent;\n"
               "                    document.getElementById('packets-received').textContent = data.packets_received;\n"
               "                })\n"
               "                .catch(err => console.error('Status update failed:', err));\n"
               "        }\n"
               "        \n"
               "        function getStatusText(state) {\n"
               "            switch(state) {\n"
               "                case 'disconnected': return '未连接';\n"
               "                case 'connecting': return '连接中...';\n"
               "                case 'authenticating': return '认证中...';\n"
               "                case 'connected': return '已连接';\n"
               "                case 'disconnecting': return '断开中...';\n"
               "                case 'error': return '连接错误';\n"
               "                default: return '未知状态';\n"
               "            }\n"
               "        }\n"
               "        \n"
               "        function formatBytes(bytes) {\n"
               "            if (bytes === 0) return '0 B';\n"
               "            const k = 1024;\n"
               "            const sizes = ['B', 'KB', 'MB', 'GB'];\n"
               "            const i = Math.floor(Math.log(bytes) / Math.log(k));\n"
               "            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];\n"
               "        }\n"
               "        \n"
               "        function connect() {\n"
               "            const server = document.getElementById('server').value;\n"
               "            const username = document.getElementById('username').value;\n"
               "            const password = document.getElementById('password').value;\n"
               "            \n"
               "            if (!server) {\n"
               "                alert('请输入服务器地址');\n"
               "                return;\n"
               "            }\n"
               "            \n"
               "            const data = {\n"
               "                server: server,\n"
               "                username: username,\n"
               "                password: password\n"
               "            };\n"
               "            \n"
               "            fetch('/api/connect', {\n"
               "                method: 'POST',\n"
               "                headers: {'Content-Type': 'application/json'},\n"
               "                body: JSON.stringify(data)\n"
               "            })\n"
               "            .then(response => response.json())\n"
               "            .then(result => {\n"
               "                if (!result.success) {\n"
               "                    alert('连接失败: ' + (result.error || '未知错误'));\n"
               "                }\n"
               "            })\n"
               "            .catch(err => alert('连接请求失败: ' + err));\n"
               "        }\n"
               "        \n"
               "        function disconnect() {\n"
               "            fetch('/api/disconnect', {method: 'POST'})\n"
               "                .then(response => response.json())\n"
               "                .then(result => {\n"
               "                    if (!result.success) {\n"
               "                        alert('断开失败');\n"
               "                    }\n"
               "                })\n"
               "                .catch(err => alert('断开请求失败: ' + err));\n"
               "        }\n"
               "        \n"
               "        function testTap() {\n"
               "            fetch('/api/test-tap', {method: 'POST'})\n"
               "                .then(response => response.json())\n"
               "                .then(result => {\n"
               "                    let message = 'TAP驱动状态:\\n';\n"
               "                    message += '已安装: ' + (result.tap_driver_installed ? '是' : '否') + '\\n';\n"
               "                    message += '版本: ' + result.driver_version + '\\n';\n"
               "                    message += '可用适配器: ' + result.available_adapters + '个';\n"
               "                    alert(message);\n"
               "                })\n"
               "                .catch(err => alert('TAP测试失败: ' + err));\n"
               "        }\n"
               "        \n"
               "        function updateLogs() {\n"
               "            fetch('/api/logs')\n"
               "                .then(response => response.json())\n"
               "                .then(data => {\n"
               "                    const logsDiv = document.getElementById('logs');\n"
               "                    logsDiv.innerHTML = data.logs.map(log => '<div>' + log + '</div>').join('');\n"
               "                    logsDiv.scrollTop = logsDiv.scrollHeight;\n"
               "                })\n"
               "                .catch(err => console.error('Logs update failed:', err));\n"
               "        }\n"
               "        \n"
               "        // 定期更新状态和日志\n"
               "        setInterval(updateStatus, 2000);\n"
               "        setInterval(updateLogs, 5000);\n"
               "        \n"
               "        // 初始化\n"
               "        updateStatus();\n"
               "        updateLogs();\n"
               "    </script>\n"
               "</body>\n"
               "</html>";
    }
    
    return "HTTP/1.1 404 Not Found\r\n"
           "Content-Type: text/plain\r\n"
           "Connection: close\r\n\r\n"
           "404 Not Found";
}

std::string SimpleWebServer::jsonResponse(const std::string& json, int status) {
    std::ostringstream response;
    response << "HTTP/1.1 " << status << " OK\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "Connection: close\r\n\r\n";
    response << json;
    return response.str();
}

std::string SimpleWebServer::errorResponse(const std::string& message, int status) {
    std::ostringstream json;
    json << "{\"error\": \"" << message << "\"}";
    return jsonResponse(json.str(), status);
}

std::string SimpleWebServer::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void SimpleWebServer::addLog(const std::string& message) {
    std::lock_guard<std::mutex> lock(logs_mutex_);
    
    std::string timestamped = "[" + getCurrentTime() + "] " + message;
    logs_.push_back(timestamped);
    
    // 限制日志数量
    if (logs_.size() > MAX_LOGS) {
        logs_.erase(logs_.begin());
    }
    
    std::cout << timestamped << std::endl;
}

} // namespace client
} // namespace sduvpn
