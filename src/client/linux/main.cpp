#include "client/linux_vpn_client.h"
#include "client/linux_tun_interface.h"
#include "common/web_server.h"
#include "common/config_manager.h"
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <thread>
#include <chrono>

using namespace sduvpn::client;
using namespace sduvpn::common;

// 全局变量用于信号处理
static std::shared_ptr<WebServer> g_web_server;
static std::shared_ptr<LinuxVPNClient> g_vpn_client;

void printUsage() {
    std::cout << "SDUVPN Linux Client\n";
    std::cout << "Usage:\n";
    std::cout << "  sduvpn-client-linux [command] [options]\n\n";
    std::cout << "Default behavior: Starts Web UI if no command is specified\n\n";
    std::cout << "Commands:\n";
    std::cout << "  connect     - Connect to VPN server\n";
    std::cout << "  disconnect  - Disconnect from VPN server\n";
    std::cout << "  status      - Show connection status\n";
    std::cout << "  webui       - Launch Web UI interface\n";
    std::cout << "  test-tun    - Test TUN interface functionality\n";
    std::cout << "  daemon      - Run as daemon with Web UI\n";
    std::cout << "  help        - Show this help message\n\n";
    std::cout << "Connect Options:\n";
    std::cout << "  --server <address>    - Server address (required)\n";
    std::cout << "  --port <port>         - Server port (default: 1194)\n";
    std::cout << "  --username <user>     - Username for authentication\n";
    std::cout << "  --password <pass>     - Password for authentication\n";
    std::cout << "  --interface <name>    - TUN interface name (optional)\n";
    std::cout << "  --config <file>       - Configuration file path\n\n";
    std::cout << "WebUI Options:\n";
    std::cout << "  --port <port>         - Web server port (default: 8080)\n";
    std::cout << "  --no-browser          - Don't open browser automatically\n\n";
    std::cout << "Note: This program requires root privileges to create TUN interfaces.\n";
}

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down gracefully..." << std::endl;
    
    if (g_web_server) {
        g_web_server->stop();
    }
    
    if (g_vpn_client) {
        g_vpn_client->disconnect();
    }
    
    exit(0);
}

void setupSignalHandlers() {
    signal(SIGINT, signalHandler);   // Ctrl+C
    signal(SIGTERM, signalHandler);  // Termination signal
    signal(SIGQUIT, signalHandler);  // Quit signal
}

bool checkSystemRequirements() {
    auto [requirements_met, error_msg] = LinuxVPNClientManager::getInstance().checkSystemRequirements();
    if (!requirements_met) {
        std::cout << "System requirements not met: " << error_msg << "\n";
        
        // 提供解决方案提示
        if (error_msg.find("Root privileges") != std::string::npos) {
            std::cout << "Please run with sudo or as root.\n";
            std::cout << "Example: sudo ./sduvpn-client-linux\n";
        } else if (error_msg.find("TUN module") != std::string::npos) {
            std::cout << "Try loading the TUN module with: sudo modprobe tun\n";
        }
        
        return false;
    }
    
    return true;
}

bool handleConnectCommand(const std::vector<std::string>& args) {
    LinuxVPNClient::LinuxConnectionConfig config;
    
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
        else if (args[i] == "--interface" && i + 1 < args.size()) {
            config.interface_name = args[++i];
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
        // 在生产环境中应该使用安全的密码输入方法
        std::getline(std::cin, config.password);
    }
    
    // 创建VPN客户端
    auto client = LinuxVPNClientManager::getInstance().createClient();
    
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
        
        if (state == LinuxVPNClient::ConnectionState::CONNECTED) {
            std::cout << "VPN connection established successfully!\n";
            
            // 显示连接信息
            auto stats = client->getConnectionStats();
            std::cout << "Connection established. Bytes sent: " << stats.bytes_sent 
                      << ", received: " << stats.bytes_received << "\n";
            std::cout << "Press Enter to disconnect...\n";
            std::cin.get();
            
            client->disconnect();
            std::cout << "VPN disconnected.\n";
            return true;
        }
        else if (state == LinuxVPNClient::ConnectionState::ERROR_STATE) {
            std::cout << "Connection failed: " << client->getLastError() << "\n";
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    std::cout << "Connection timeout.\n";
    client->disconnect();
    return false;
}

bool handleTestTunCommand() {
    std::cout << "Testing TUN interface functionality...\n";
    
    // 检查TUN模块是否可用
    if (!LinuxTunInterface::isTunModuleAvailable()) {
        std::cout << "TUN module is not available.\n";
        std::cout << "Please load TUN module: sudo modprobe tun\n";
        return false;
    }
    
    std::cout << "TUN module is available.\n";
    
    // 检查权限
    if (!LinuxTunInterface::hasRootPrivileges()) {
        std::cout << "Root privileges required for TUN interface operations.\n";
        std::cout << "Please run with sudo.\n";
        return false;
    }
    
    std::cout << "Root privileges: OK\n";
    
    // 获取可用接口
    auto interfaces = LinuxTunInterface::getAvailableInterfaces();
    std::cout << "Available TUN interfaces: " << interfaces.size() << "\n";
    
    for (size_t i = 0; i < interfaces.size(); i++) {
        std::cout << "  " << i + 1 << ". " << interfaces[i] << "\n";
    }
    
    // 测试创建TUN接口
    LinuxTunInterface tun_interface;
    if (!tun_interface.openInterface()) {
        std::cout << "Failed to create TUN interface: " << tun_interface.getLastError() << "\n";
        return false;
    }
    
    std::cout << "Successfully created TUN interface: " << tun_interface.getInterfaceName() << "\n";
    
    // 设置测试IP地址
    if (tun_interface.setIPAddress("10.8.0.2", "255.255.255.0")) {
        std::cout << "IP address set successfully.\n";
    } else {
        std::cout << "Failed to set IP address: " << tun_interface.getLastError() << "\n";
    }
    
    // 激活接口
    if (tun_interface.setInterfaceStatus(true)) {
        std::cout << "Interface activated successfully.\n";
    } else {
        std::cout << "Failed to activate interface: " << tun_interface.getLastError() << "\n";
    }
    
    std::cout << "TUN interface test completed.\n";
    return true;
}

bool handleWebUICommand(const std::vector<std::string>& args) {
    std::cout << "Starting Web UI...\n";
    
    // 解析WebUI选项
    uint16_t web_port = 8080;
    bool open_browser = true;
    
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--port" && i + 1 < args.size()) {
            web_port = static_cast<uint16_t>(std::stoi(args[++i]));
        }
        else if (args[i] == "--no-browser") {
            open_browser = false;
        }
    }
    
    // 创建VPN客户端实例
    g_vpn_client = LinuxVPNClientManager::getInstance().createClient();
    
    // 创建配置管理器
    auto configManager = std::make_shared<ConfigManager>();
    if (!configManager->initialize()) {
        std::cout << "Warning: Failed to initialize config manager\n";
    }
    
    // 创建Web服务器
    g_web_server = std::make_shared<WebServer>();
    g_web_server->setVPNClient(g_vpn_client);
    g_web_server->setConfigManager(configManager);
    
    // 设置日志回调
    g_web_server->setLogCallback([](const std::string& message) {
        std::cout << "[WebUI] " << message << std::endl;
    });
    
    // 启动Web服务器（尝试多个端口）
    uint16_t ports[] = {web_port, 8081, 8082, 9090, 9091};
    bool started = false;
    
    for (uint16_t port : ports) {
        if (g_web_server->start(port)) {
            started = true;
            break;
        }
        std::cout << "Port " << port << " failed, trying next...\n";
    }
    
    if (!started) {
        std::cout << "Failed to start web server on any available port.\n";
        std::cout << "Please check if ports are available or run with different --port option.\n";
        return false;
    }
    
    std::cout << "Web UI started successfully!\n";
    std::cout << "Open your browser and go to: " << g_web_server->getURL() << "\n";
    std::cout << "\nPress Ctrl+C to stop the web server...\n";
    
    // 尝试自动打开浏览器
    if (open_browser && g_web_server->openInBrowser()) {
        std::cout << "Browser opened automatically.\n";
    } else {
        std::cout << "Please manually open the URL in your browser.\n";
    }
    
    // 等待信号
    while (g_web_server->isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "Web UI stopped.\n";
    return true;
}

bool handleDaemonCommand(const std::vector<std::string>& args) {
    std::cout << "Starting SDUVPN daemon...\n";
    
    // 创建守护进程
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Failed to fork daemon process\n";
        return false;
    }
    
    if (pid > 0) {
        // 父进程退出
        std::cout << "Daemon started with PID: " << pid << "\n";
        exit(0);
    }
    
    // 子进程继续执行
    setsid(); // 创建新会话
    
    // 改变工作目录到根目录
    if (chdir("/") != 0) {
        std::cerr << "Warning: Failed to change working directory to /\n";
    }
    
    // 关闭标准输入输出（可选，这里保留用于调试）
    // close(STDIN_FILENO);
    // close(STDOUT_FILENO);
    // close(STDERR_FILENO);
    
    // 启动WebUI
    return handleWebUICommand(args);
}

bool handleStatusCommand() {
    std::cout << "VPN Client Status:\n";
    
    // 检查系统要求
    auto [requirements_met, error_msg] = LinuxVPNClientManager::getInstance().checkSystemRequirements();
    std::cout << "System Requirements: " << (requirements_met ? "OK" : "FAILED") << "\n";
    if (!requirements_met) {
        std::cout << "  Error: " << error_msg << "\n";
    }
    
    // 检查TUN接口
    auto interfaces = LinuxTunInterface::getAvailableInterfaces();
    std::cout << "Available TUN interfaces: " << interfaces.size() << "\n";
    for (const auto& iface : interfaces) {
        std::cout << "  - " << iface << "\n";
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    // 设置信号处理
    setupSignalHandlers();
    
    // 转换命令行参数
    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    // 如果没有参数，默认启动Web UI
    if (argc == 1) {
        std::cout << "SDUVPN Linux Client - Starting Web UI by default\n";
        std::cout << "Use 'sduvpn-client-linux help' to see all available commands\n\n";
        
        // 检查系统要求
        if (!checkSystemRequirements()) {
            return 1;
        }
        
        return handleWebUICommand(args) ? 0 : 1;
    }
    
    std::string command = args[1];
    
    if (command == "help" || command == "--help" || command == "-h") {
        printUsage();
        return 0;
    }
    else if (command == "connect") {
        if (!checkSystemRequirements()) {
            return 1;
        }
        return handleConnectCommand(args) ? 0 : 1;
    }
    else if (command == "test-tun") {
        return handleTestTunCommand() ? 0 : 1;
    }
    else if (command == "webui") {
        if (!checkSystemRequirements()) {
            return 1;
        }
        return handleWebUICommand(args) ? 0 : 1;
    }
    else if (command == "daemon") {
        if (!checkSystemRequirements()) {
            return 1;
        }
        return handleDaemonCommand(args) ? 0 : 1;
    }
    else if (command == "status") {
        return handleStatusCommand() ? 0 : 1;
    }
    else if (command == "disconnect") {
        std::cout << "Disconnect command not implemented in CLI mode.\n";
        std::cout << "Use Web UI to manage connections.\n";
        return 1;
    }
    else {
        std::cout << "Unknown command: " << command << "\n";
        printUsage();
        return 1;
    }
    
    return 0;
}
