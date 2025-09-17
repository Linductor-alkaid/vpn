#include "client/windows_service.h"
#include "client/windows_vpn_client.h"
#include "client/windows_tap_interface.h"
#include "client/web_server.h"
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <windows.h>

using namespace sduvpn::client;

void printUsage() {
    std::cout << "SDUVPN Windows Client\n";
    std::cout << "Usage:\n";
    std::cout << "  sduvpn-client.exe [command] [options]\n\n";
    std::cout << "Default behavior: Starts Web UI if no command is specified\n\n";
    std::cout << "Commands:\n";
    std::cout << "  connect     - Connect to VPN server\n";
    std::cout << "  disconnect  - Disconnect from VPN server\n";
    std::cout << "  status      - Show connection status\n";
    std::cout << "  webui       - Launch Web UI interface\n";
    std::cout << "  gui         - Launch GUI interface (deprecated)\n";
    std::cout << "  service     - Service management commands\n";
    std::cout << "  test-tap    - Test TAP adapter functionality\n";
    std::cout << "  help        - Show this help message\n\n";
    std::cout << "Service Commands:\n";
    std::cout << "  service install   - Install Windows service\n";
    std::cout << "  service uninstall - Uninstall Windows service\n";
    std::cout << "  service start     - Start Windows service\n";
    std::cout << "  service stop      - Stop Windows service\n";
    std::cout << "  service status    - Show service status\n\n";
    std::cout << "Connect Options:\n";
    std::cout << "  --server <address>    - Server address (required)\n";
    std::cout << "  --port <port>         - Server port (default: 1194)\n";
    std::cout << "  --username <user>     - Username for authentication\n";
    std::cout << "  --password <pass>     - Password for authentication\n";
    std::cout << "  --adapter <name>      - TAP adapter name (optional)\n";
    std::cout << "  --config <file>       - Configuration file path\n";
}

bool handleServiceCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Service command required. Use 'service help' for options.\n";
        return false;
    }
    
    std::string service_cmd = args[1];
    
    if (service_cmd == "install") {
        char exe_path[MAX_PATH];
        GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        
        if (ServiceManager::installSDUVPNService(exe_path)) {
            std::cout << "Service installed successfully.\n";
            return true;
        } else {
            std::cout << "Failed to install service.\n";
            return false;
        }
    }
    else if (service_cmd == "uninstall") {
        if (ServiceManager::uninstallSDUVPNService()) {
            std::cout << "Service uninstalled successfully.\n";
            return true;
        } else {
            std::cout << "Failed to uninstall service.\n";
            return false;
        }
    }
    else if (service_cmd == "start") {
        if (ServiceManager::startSDUVPNService()) {
            std::cout << "Service started successfully.\n";
            return true;
        } else {
            std::cout << "Failed to start service.\n";
            return false;
        }
    }
    else if (service_cmd == "stop") {
        if (ServiceManager::stopSDUVPNService()) {
            std::cout << "Service stopped successfully.\n";
            return true;
        } else {
            std::cout << "Failed to stop service.\n";
            return false;
        }
    }
    else if (service_cmd == "status") {
        std::string status = ServiceManager::getSDUVPNServiceStatus();
        std::cout << "Service Status: " << status << "\n";
        return true;
    }
    else {
        std::cout << "Unknown service command: " << service_cmd << "\n";
        return false;
    }
}

bool handleConnectCommand(const std::vector<std::string>& args) {
    WindowsVPNClient::ConnectionConfig config;
    
    // 解析命令行参数
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--server" && i + 1 < args.size()) {
            config.server_address = args[++i];
        }
        else if (args[i] == "--port" && i + 1 < args.size()) {
            config.server_port = static_cast<uint16_t>(std::stoi(args[++i]));
        }
        else if (args[i] == "--username" && i + 1 < args.size()) {
            config.username = args[++i];
        }
        else if (args[i] == "--password" && i + 1 < args.size()) {
            config.password = args[++i];
        }
        else if (args[i] == "--adapter" && i + 1 < args.size()) {
            config.tap_adapter_name = args[++i];
        }
    }
    
    if (config.server_address.empty()) {
        std::cout << "Server address is required. Use --server <address>\n";
        return false;
    }
    
    if (config.username.empty()) {
        std::cout << "Username: ";
        std::getline(std::cin, config.username);
    }
    
    if (config.password.empty()) {
        std::cout << "Password: ";
        // 这里应该使用安全的密码输入方法
        std::getline(std::cin, config.password);
    }
    
    // 创建VPN客户端
    auto client = WindowsVPNClientManager::getInstance().createClient();
    
    // 设置日志回调
    client->setLogCallback([](const std::string& message) {
        std::cout << "[VPN] " << message << std::endl;
    });
    
    std::cout << "Connecting to " << config.server_address << ":" << config.server_port << "...\n";
    
    if (!client->connect(config)) {
        std::cout << "Failed to start connection: " << client->getLastError() << "\n";
        return false;
    }
    
    // 等待连接建立或失败
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(30);
    
    while (std::chrono::steady_clock::now() - start_time < timeout) {
        auto state = client->getConnectionState();
        
        if (state == WindowsVPNClient::ConnectionState::CONNECTED) {
            std::cout << "VPN connection established successfully!\n";
            
            // 显示连接信息
            auto stats = client->getConnectionStats();
            std::cout << "Press Enter to disconnect...\n";
            std::cin.get();
            
            client->disconnect();
            std::cout << "VPN disconnected.\n";
            return true;
        }
        else if (state == WindowsVPNClient::ConnectionState::ERROR_STATE) {
            std::cout << "Connection failed: " << client->getLastError() << "\n";
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    std::cout << "Connection timeout.\n";
    client->disconnect();
    return false;
}

bool handleTestTapCommand() {
    std::cout << "Testing TAP adapter functionality...\n";
    
    // 检查TAP驱动是否已安装
    if (!TapAdapterManager::isTapDriverInstalled()) {
        std::cout << "TAP-Windows driver is not installed.\n";
        std::cout << "Please install TAP-Windows driver first.\n";
        return false;
    }
    
    std::cout << "TAP driver version: " << TapAdapterManager::getTapDriverVersion() << "\n";
    
    // 获取可用适配器
    auto adapters = TapAdapterManager::getAvailableAdapters();
    std::cout << "Available TAP adapters: " << adapters.size() << "\n";
    
    for (size_t i = 0; i < adapters.size(); i++) {
        std::cout << "  " << i + 1 << ". " << adapters[i] << "\n";
    }
    
    if (adapters.empty()) {
        std::cout << "No TAP adapters found.\n";
        return false;
    }
    
    // 测试第一个适配器
    WindowsTapInterface tap_interface;
    if (!tap_interface.openAdapter()) {
        std::cout << "Failed to open TAP adapter: " << tap_interface.getLastError() << "\n";
        return false;
    }
    
    std::cout << "Successfully opened TAP adapter: " << tap_interface.getAdapterName() << "\n";
    std::cout << "Adapter GUID: " << tap_interface.getAdapterGUID() << "\n";
    
    // 设置测试IP地址
    if (tap_interface.setIPAddress("10.8.0.2", "255.255.255.0")) {
        std::cout << "IP address set successfully.\n";
    } else {
        std::cout << "Failed to set IP address: " << tap_interface.getLastError() << "\n";
    }
    
    // 激活适配器
    if (tap_interface.setAdapterStatus(true)) {
        std::cout << "Adapter activated successfully.\n";
    } else {
        std::cout << "Failed to activate adapter: " << tap_interface.getLastError() << "\n";
    }
    
    std::cout << "TAP adapter test completed.\n";
    return true;
}

bool handleWebUICommand() {
    std::cout << "Starting Web UI...\n";
    
    // 创建VPN客户端实例
    auto client_unique = WindowsVPNClientManager::getInstance().createClient();
    auto client = std::shared_ptr<WindowsVPNClient>(client_unique.release());
    
    // 创建Web服务器
    auto webServer = std::make_shared<SimpleWebServer>();
    webServer->setVPNClient(client);
    
    // 启动Web服务器（尝试多个端口）
    uint16_t ports[] = {8080, 8081, 8082, 9090, 9091};
    bool started = false;
    
    for (uint16_t port : ports) {
        if (webServer->start(port)) {
            started = true;
            break;
        }
        std::cout << "Port " << port << " failed, trying next...\n";
    }
    
    if (!started) {
        std::cout << "Failed to start web server on any available port.\n";
        std::cout << "Please run as Administrator or check if ports are available.\n";
        return false;
    }
    
    std::cout << "Web UI started successfully!\n";
    std::cout << "Open your browser and go to: " << webServer->getURL() << "\n";
    std::cout << "\nPress Enter to stop the web server...\n";
    
    // 尝试自动打开浏览器
    if (webServer->openInBrowser()) {
        std::cout << "Browser opened automatically.\n";
    } else {
        std::cout << "Please manually open the URL in your browser.\n";
    }
    
    // 等待用户按Enter键
    std::cin.get();
    
    std::cout << "Stopping web server...\n";
    webServer->stop();
    std::cout << "Web UI stopped.\n";
    
    return true;
}

bool runAsService() {
    // 检查是否以服务方式运行
    SERVICE_TABLE_ENTRYA service_table[] = {
        { const_cast<char*>(SDUVPNWindowsService::SERVICE_NAME), 
          reinterpret_cast<LPSERVICE_MAIN_FUNCTIONA>(WindowsServiceBase::serviceMain) },
        { nullptr, nullptr }
    };
    
    return StartServiceCtrlDispatcherA(service_table) == TRUE;
}

int main(int argc, char* argv[]) {
    // 检查系统要求
    auto [requirements_met, error_msg] = WindowsVPNClientManager::getInstance().checkSystemRequirements();
    if (!requirements_met) {
        std::cout << "System requirements not met: " << error_msg << "\n";
        
        // 如果是权限问题，尝试提示用户
        if (error_msg.find("Administrator") != std::string::npos) {
            std::cout << "Please run as Administrator.\n";
            return 1;
        }
    }
    
    // 转换命令行参数
    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    // 如果没有参数，默认启动Web UI
    if (argc == 1) {
        // 首先尝试作为服务运行
        if (runAsService()) {
            return 0;
        }
        
        // 如果不是服务模式，启动Web UI
        std::cout << "SDUVPN Windows Client - Starting Web UI by default\n";
        std::cout << "Use 'sduvpn-client.exe help' to see all available commands\n\n";
        
        return handleWebUICommand() ? 0 : 1;
    }
    
    std::string command = args[1];
    
    if (command == "help" || command == "--help" || command == "-h") {
        printUsage();
        return 0;
    }
    else if (command == "service") {
        return handleServiceCommand(args) ? 0 : 1;
    }
    else if (command == "connect") {
        return handleConnectCommand(args) ? 0 : 1;
    }
    else if (command == "test-tap") {
        return handleTestTapCommand() ? 0 : 1;
    }
    else if (command == "webui") {
        return handleWebUICommand() ? 0 : 1;
    }
    else if (command == "gui") {
        std::cout << "GUI mode deprecated. Use 'webui' command instead.\n";
        return handleWebUICommand() ? 0 : 1;
    }
    else if (command == "status") {
        std::cout << "Status command not implemented yet.\n";
        return 1;
    }
    else {
        std::cout << "Unknown command: " << command << "\n";
        printUsage();
        return 1;
    }
    
    return 0;
}
