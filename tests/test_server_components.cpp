#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <chrono>
#include <thread>

// 包含服务器组件头文件
#include "server/server_config.h"
#include "server/client_session.h"
#include "server/packet_router.h"

using namespace sduvpn::server;

// 简单测试框架
class TestRunner {
private:
    static int tests_run;
    static int tests_passed;

public:
    static void run_test(const std::string& test_name, std::function<bool()> test_func) {
        tests_run++;
        std::cout << "[TEST] " << test_name << " ... ";
        
        try {
            if (test_func()) {
                std::cout << "PASSED" << std::endl;
                tests_passed++;
            } else {
                std::cout << "FAILED" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "EXCEPTION: " << e.what() << std::endl;
        } catch (...) {
            std::cout << "UNKNOWN EXCEPTION" << std::endl;
        }
    }
    
    static void print_summary() {
        std::cout << "\n=== Server Component Test Summary ===" << std::endl;
        std::cout << "Total: " << tests_run << " tests" << std::endl;
        std::cout << "Passed: " << tests_passed << " tests" << std::endl;
        std::cout << "Failed: " << (tests_run - tests_passed) << " tests" << std::endl;
        std::cout << "Success Rate: " << (tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0) << "%" << std::endl;
    }
    
    static bool all_passed() {
        return tests_run == tests_passed;
    }
};

int TestRunner::tests_run = 0;
int TestRunner::tests_passed = 0;

// 测试服务器配置
bool test_server_config() {
    ServerConfig config;
    
    // 测试默认配置
    if (config.getListenPort() != 1194) return false;
    if (config.getMaxClients() != 100) return false;
    if (config.getVirtualNetwork() != "10.8.0.0") return false;
    
    // 测试配置修改
    config.setListenPort(8080);
    config.setMaxClients(50);
    config.setDebugMode(true);
    
    if (config.getListenPort() != 8080) return false;
    if (config.getMaxClients() != 50) return false;
    if (!config.isDebugMode()) return false;
    
    // 测试配置验证
    return config.validate();
}

// 测试用户管理
bool test_user_management() {
    ServerConfig config;
    
    // 添加用户
    config.addUser("testuser1", "password123");
    config.addUser("testuser2", "password456");
    
    // 验证用户
    if (!config.verifyUser("testuser1", "password123")) return false;
    if (!config.verifyUser("testuser2", "password456")) return false;
    if (config.verifyUser("testuser1", "wrongpassword")) return false;
    if (config.verifyUser("nonexistent", "password123")) return false;
    
    // 删除用户
    config.removeUser("testuser1");
    if (config.verifyUser("testuser1", "password123")) return false;
    if (!config.verifyUser("testuser2", "password456")) return false;
    
    return true;
}

// 测试客户端会话
bool test_client_session() {
    ClientSession session(12345);
    
    // 测试基本属性
    if (session.getClientId() != 12345) return false;
    if (session.getState() != SessionState::CONNECTING) return false;
    
    // 测试状态变更
    session.setState(SessionState::AUTHENTICATING);
    if (session.getState() != SessionState::AUTHENTICATING) return false;
    
    // 测试虚拟IP分配
    session.assignVirtualIP("10.8.0.100");
    if (session.getVirtualIP() != "10.8.0.100") return false;
    
    // 测试认证
    if (!session.authenticate("testuser", "testpass", "v1.0|device123")) return false;
    if (session.getAuthInfo().username != "testuser") return false;
    
    // 测试活跃时间更新
    auto old_activity = session.getLastActivity();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    session.updateLastActivity();
    if (session.getLastActivity() <= old_activity) return false;
    
    // 测试过期检查
    if (session.isExpired(3600)) return false;  // 1小时内不应过期
    
    return true;
}

// 测试数据包路由器
bool test_packet_router() {
    PacketRouter router;
    
    // 初始化路由器
    if (!router.initialize("10.8.0.0", "255.255.255.0")) return false;
    
    // 测试虚拟网络检查
    if (!router.isInVirtualNetwork("10.8.0.1")) return false;
    if (!router.isInVirtualNetwork("10.8.0.255")) return false;
    if (router.isInVirtualNetwork("192.168.1.1")) return false;
    if (router.isInVirtualNetwork("10.9.0.1")) return false;
    
    // 测试静态路由
    RouteEntry route("192.168.1.0", "255.255.255.0", "10.8.0.1", "eth0", 10, 0);
    if (!router.addStaticRoute(route)) return false;
    
    const RouteEntry* found_route = router.findRoute("192.168.1.100");
    if (!found_route) return false;
    if (found_route->network != "192.168.1.0") return false;
    
    // 测试路由表
    auto route_table = router.getRouteTable();
    if (route_table.empty()) return false;
    
    return true;
}

// 测试客户端路由管理
bool test_client_routing() {
    PacketRouter router;
    router.initialize("10.8.0.0", "255.255.255.0");
    
    // 创建模拟客户端会话
    auto session1 = std::make_shared<ClientSession>(1001);
    auto session2 = std::make_shared<ClientSession>(1002);
    
    session1->assignVirtualIP("10.8.0.101");
    session2->assignVirtualIP("10.8.0.102");
    
    // 添加客户端路由
    router.addClientRoute(1001, "10.8.0.101", session1);
    router.addClientRoute(1002, "10.8.0.102", session2);
    
    // 测试客户端查找
    auto result1 = router.findClientByIP("10.8.0.101");
    if (result1 != 1001) {
        std::cout << "DEBUG: Expected client 1001 for IP 10.8.0.101, got " << result1 << std::endl;
        return false;
    }
    
    auto result2 = router.findClientByIP("10.8.0.102");
    if (result2 != 1002) {
        std::cout << "DEBUG: Expected client 1002 for IP 10.8.0.102, got " << result2 << std::endl;
        return false;
    }
    
    auto result3 = router.findClientByIP("10.8.0.103");
    if (result3 != 0) {
        std::cout << "DEBUG: Expected client 0 for IP 10.8.0.103, got " << result3 << std::endl;
        return false;
    }
    
    // 测试会话获取
    auto retrieved_session = router.getClientSession(1001);
    if (!retrieved_session) {
        std::cout << "DEBUG: Failed to retrieve session for client 1001" << std::endl;
        return false;
    }
    if (retrieved_session->getClientId() != 1001) {
        std::cout << "DEBUG: Retrieved session has wrong client ID: " << retrieved_session->getClientId() << std::endl;
        return false;
    }
    
    // 删除客户端路由
    router.removeClientRoute(1001);
    if (router.findClientByIP("10.8.0.101") != 0){
        std::cout << "DEBUG: Expected client 0 for IP 10.8.0.101, got " << router.findClientByIP("10.8.0.101") << std::endl;
        return false;
    } 
    if (router.findClientByIP("10.8.0.102") != 1002) {
        std::cout << "DEBUG: Expected client 1002 for IP 10.8.0.102, got " << router.findClientByIP("10.8.0.102") << std::endl;
        return false;
    }
    
    return true;
}

// 测试统计功能
bool test_statistics() {
    PacketRouter router;
    router.initialize("10.8.0.0", "255.255.255.0");
    
    // 获取初始统计
    auto initial_stats = router.getStats();
    if (initial_stats.packets_routed != 0) return false;
    
    // 重置统计
    router.resetStats();
    auto reset_stats = router.getStats();
    if (reset_stats.packets_routed != 0) return false;
    
    return true;
}

// 测试配置文件格式（JSON字符串）
bool test_config_json() {
    ServerConfig config;
    
    std::string json_config = R"({
        "network": {
            "listen_port": 9999,
            "bind_address": "127.0.0.1"
        },
        "virtual_network": {
            "network": "172.16.0.0",
            "netmask": "255.255.0.0",
            "interface_name": "test-tun0"
        },
        "clients": {
            "max_clients": 200,
            "timeout_seconds": 600
        },
        "authentication": {
            "required": true,
            "users": [
                {"username": "admin", "password": "admin123"},
                {"username": "user1", "password": "user123"}
            ]
        },
        "debug": {
            "debug_mode": true
        }
    })";
    
    if (!config.loadFromString(json_config)) return false;
    
    // 验证加载的配置
    if (config.getListenPort() != 9999) return false;
    if (config.getBindAddress() != "127.0.0.1") return false;
    if (config.getVirtualNetwork() != "172.16.0.0") return false;
    if (config.getVirtualNetmask() != "255.255.0.0") return false;
    if (config.getTunInterfaceName() != "test-tun0") return false;
    if (config.getMaxClients() != 200) return false;
    if (config.getClientTimeoutSeconds() != 600) return false;
    if (!config.isDebugMode()) return false;
    
    // 验证用户
    if (!config.verifyUser("admin", "admin123")) return false;
    if (!config.verifyUser("user1", "user123")) return false;
    
    return config.validate();
}

int main() {
    std::cout << "SDUVPN Server Components Test Suite" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << std::endl;
    
    // 运行所有测试
    TestRunner::run_test("Server Configuration", test_server_config);
    TestRunner::run_test("User Management", test_user_management);
    TestRunner::run_test("Client Session", test_client_session);
    TestRunner::run_test("Packet Router", test_packet_router);
    TestRunner::run_test("Client Routing", test_client_routing);
    TestRunner::run_test("Statistics", test_statistics);
    TestRunner::run_test("JSON Configuration", test_config_json);
    
    // 打印测试结果
    TestRunner::print_summary();
    
    return TestRunner::all_passed() ? 0 : 1;
}
