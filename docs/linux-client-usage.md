# SDUVPN Linux客户端使用指南

## 概述

SDUVPN Linux客户端是一个功能完整的VPN客户端，支持TUN接口和Web管理界面。它与Windows客户端共享相同的WebUI代码，确保了一致的用户体验。

## 系统要求

- Linux内核支持TUN模块
- Root权限（用于创建TUN接口）
- C++17编译器
- CMake 3.10+

## 编译

```bash
# 在项目根目录下
mkdir build && cd build
cmake ..
make sduvpn-client-linux
```

## 安装

```bash
sudo make install
```

## 使用方法

### 基本用法

```bash
# 显示帮助信息
./sduvpn-client-linux help

# 启动Web UI（默认行为）
./sduvpn-client-linux
# 或
./sduvpn-client-linux webui

# 连接到VPN服务器
sudo ./sduvpn-client-linux connect --server vpn.example.com --username myuser

# 检查系统状态
./sduvpn-client-linux status

# 测试TUN接口
sudo ./sduvpn-client-linux test-tun
```

### Web UI模式

Web UI是推荐的使用方式，提供友好的图形界面：

```bash
# 启动Web UI（默认端口8080）
sudo ./sduvpn-client-linux webui

# 指定端口
sudo ./sduvpn-client-linux webui --port 9090

# 不自动打开浏览器
sudo ./sduvpn-client-linux webui --no-browser
```

启动后，打开浏览器访问 `http://localhost:8080`

### 守护进程模式

```bash
# 以守护进程运行
sudo ./sduvpn-client-linux daemon
```

### 命令行连接模式

```bash
# 基本连接
sudo ./sduvpn-client-linux connect \
    --server vpn.example.com \
    --username myuser \
    --password mypass

# 指定端口和接口
sudo ./sduvpn-client-linux connect \
    --server vpn.example.com \
    --port 1194 \
    --username myuser \
    --password mypass \
    --interface tun0
```

## 配置文件

配置文件存储在 `~/.config/sduvpn/` 目录下，使用JSON格式。

示例配置文件：
```json
{
  "name": "My VPN Server",
  "server_address": "vpn.example.com",
  "server_port": 1194,
  "username": "myuser",
  "password": "encrypted_password",
  "interface_name": "tun0",
  "virtual_ip": "10.8.0.2",
  "virtual_netmask": "255.255.255.0",
  "keepalive_interval": 30,
  "connection_timeout": 10,
  "auto_reconnect": true,
  "max_reconnect_attempts": 5
}
```

## 权限要求

Linux客户端需要root权限来：
- 创建和配置TUN接口
- 设置路由表
- 绑定特权端口（如果需要）

建议使用sudo运行：
```bash
sudo ./sduvpn-client-linux
```

## TUN模块

确保TUN模块已加载：
```bash
# 检查模块
lsmod | grep tun

# 加载模块
sudo modprobe tun

# 检查设备文件
ls -l /dev/net/tun
```

## 防火墙配置

如果使用防火墙，需要允许：
- VPN服务器端口（通常是UDP 1194）
- Web UI端口（默认TCP 8080）

示例iptables规则：
```bash
# 允许VPN流量
sudo iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT
sudo iptables -A INPUT -p udp --sport 1194 -j ACCEPT

# 允许Web UI
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

## 故障排除

### 常见问题

1. **权限被拒绝**
   ```
   解决方案：使用sudo运行程序
   ```

2. **TUN模块未找到**
   ```bash
   sudo modprobe tun
   ```

3. **端口被占用**
   ```bash
   # 检查端口使用情况
   netstat -tulpn | grep 8080
   
   # 使用不同端口
   ./sduvpn-client-linux webui --port 9090
   ```

4. **连接超时**
   - 检查服务器地址和端口
   - 确认防火墙设置
   - 检查网络连接

### 调试信息

启用详细日志输出：
```bash
# Web UI模式会显示详细日志
sudo ./sduvpn-client-linux webui
```

检查系统日志：
```bash
journalctl -f | grep sduvpn
```

## Web UI功能

Web UI提供以下功能：
- 连接状态监控
- 连接统计信息
- 配置文件管理
- 带宽测试
- 连接日志查看
- TUN接口测试

## 与Windows客户端的差异

Linux客户端与Windows客户端的主要差异：
- 使用TUN接口而非TAP适配器
- 需要root权限
- 配置文件位置不同
- 系统集成方式不同

但Web UI界面和功能完全相同，确保了一致的用户体验。

## 技术架构

Linux客户端采用以下架构：
- **LinuxVPNClient**: 主要的VPN客户端类
- **LinuxTunInterface**: TUN接口管理
- **WebServer**: 通用Web服务器（来自common模块）
- **ConfigManager**: 通用配置管理器（来自common模块）

## 安全注意事项

- 密码在配置文件中加密存储
- 使用安全的握手协议
- 所有数据传输都经过加密
- 建议定期更新密码
- 不要在不安全的网络上使用Web UI

## 支持和反馈

如有问题或建议，请提交issue或联系开发团队。
