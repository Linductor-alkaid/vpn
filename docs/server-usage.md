# SDUVPN 服务器使用说明

## 概述

SDUVPN 服务器是一个高性能的 VPN 服务器实现，支持多客户端连接、用户认证、数据加密和路由转发。服务器使用 UDP 协议进行通信，创建 TUN 虚拟网络接口来处理网络流量。

## 功能特性

### 核心功能
- **多客户端支持**: 同时支持多个客户端连接（默认最大 100 个）
- **用户认证**: 支持用户名/密码认证机制
- **数据加密**: 使用现代加密算法保护数据传输
- **虚拟网络**: 创建虚拟 IP 网络，为客户端分配虚拟 IP 地址
- **数据路由**: 智能路由数据包到正确的目标
- **实时监控**: 提供连接状态和流量统计信息

### 网络架构
- **协议**: UDP 协议，默认端口 1194
- **虚拟网络**: 默认使用 10.8.0.0/24 网段
- **接口**: 创建 TUN 虚拟网络接口（默认 sduvpn0）
- **路由**: 自动处理客户端间和外网的数据包路由

## 编译和安装

### 前置要求
- CMake 3.10 或更高版本
- C++17 兼容的编译器
- 管理员权限（用于创建网络接口）

### 编译步骤
```bash
# 进入项目目录
cd sduvpn

# 创建构建目录
mkdir build && cd build

# 生成构建文件
cmake ..

# 编译
cmake --build . --config Release

# 编译后的可执行文件位于 build/bin/ 目录
```

## 配置文件

### 配置文件格式
服务器使用 JSON 格式的配置文件。示例配置文件位于 `config/server.json.example`：

```json
{
  "network": {
    "listen_port": 1194,
    "bind_address": "0.0.0.0"
  },
  "virtual_network": {
    "network": "10.8.0.0",
    "netmask": "255.255.255.0",
    "interface_name": "sduvpn0"
  },
  "clients": {
    "max_clients": 100,
    "timeout_seconds": 300
  },
  "security": {
    "server_certificate": "/etc/sduvpn/server.crt",
    "server_private_key": "/etc/sduvpn/server.key",
    "ca_certificate": "/etc/sduvpn/ca.crt"
  },
  "authentication": {
    "required": true,
    "users": [
      {
        "username": "user1",
        "password": "password1"
      },
      {
        "username": "user2",
        "password": "password2"
      }
    ]
  },
  "logging": {
    "level": "info",
    "file": "/var/log/sduvpn/server.log",
    "console": true
  },
  "performance": {
    "worker_threads": 4,
    "receive_buffer_size": 65536,
    "send_buffer_size": 65536
  },
  "debug": {
    "debug_mode": false,
    "packet_dump": false
  }
}
```

### 配置参数说明

#### 网络配置 (network)
- `listen_port`: 服务器监听端口（默认 1194）
- `bind_address`: 绑定的 IP 地址（0.0.0.0 表示所有接口）

#### 虚拟网络配置 (virtual_network)
- `network`: 虚拟网络地址（如 10.8.0.0）
- `netmask`: 子网掩码（如 255.255.255.0）
- `interface_name`: TUN 接口名称（如 sduvpn0）

#### 客户端管理 (clients)
- `max_clients`: 最大客户端连接数
- `timeout_seconds`: 客户端超时时间（秒）

#### 安全配置 (security)
- `server_certificate`: 服务器证书文件路径
- `server_private_key`: 服务器私钥文件路径
- `ca_certificate`: CA 证书文件路径

#### 认证配置 (authentication)
- `required`: 是否要求用户认证
- `users`: 用户列表，包含用户名和密码

#### 日志配置 (logging)
- `level`: 日志级别（trace, debug, info, warn, error, critical）
- `file`: 日志文件路径
- `console`: 是否输出到控制台

#### 性能配置 (performance)
- `worker_threads`: 工作线程数
- `receive_buffer_size`: 接收缓冲区大小（字节）
- `send_buffer_size`: 发送缓冲区大小（字节）

#### 调试配置 (debug)
- `debug_mode`: 是否启用调试模式
- `packet_dump`: 是否启用数据包转储

## 启动服务器

### 命令行参数
服务器支持以下命令行参数：

```bash
sduvpn-server [选项]

选项:
  -c, --config FILE    指定配置文件路径
  -p, --port PORT      指定监听端口 (默认: 1194)
  -n, --network CIDR   指定虚拟网络 (默认: 10.8.0.0/24)
  -i, --interface NAME 指定 TUN 接口名称 (默认: sduvpn0)
  -d, --debug          启用调试模式
  -h, --help           显示帮助信息
```

### 启动示例

#### 使用配置文件启动
```bash
# 使用指定配置文件
sudo ./sduvpn-server -c /etc/sduvpn/server.json

# 使用默认配置文件
sudo ./sduvpn-server -c ../config/server.json.example
```

#### 使用命令行参数启动
```bash
# 指定端口和网络
sudo ./sduvpn-server -p 1194 -n 10.8.0.0/24

# 启用调试模式
sudo ./sduvpn-server -p 1194 -n 10.8.0.0/24 -d

# 指定 TUN 接口名称
sudo ./sduvpn-server -p 1194 -n 10.8.0.0/24 -i vpn0
```

### 权限要求
服务器需要管理员权限来：
- 创建和配置 TUN 网络接口
- 绑定到指定端口（如果端口 < 1024）
- 修改系统网络配置

在 Linux/macOS 上使用 `sudo` 运行：
```bash
sudo ./sduvpn-server -c server.json
```

在 Windows 上需要以管理员身份运行命令提示符或 PowerShell。

## 运行状态监控

### 服务器信息显示
服务器启动时会显示配置信息：
```
========================================
         SDUVPN Server Information
========================================
Status: Running
Listen Port: 1194
Bind Address: 0.0.0.0
Virtual Network: 10.8.0.0/255.255.255.0
TUN Interface: sduvpn0
Max Clients: 100
Client Timeout: 300 seconds
Worker Threads: 4
Debug Mode: Disabled
========================================
```

### 实时统计信息
服务器每 30 秒显示一次统计信息：
```
========================================
Server Statistics (Uptime: 120 seconds)
Active Clients: 3
Total Sent: 1048576 bytes, 512 packets
Total Received: 2097152 bytes, 1024 packets
Send Rate: 8192 B/s, 4 pps
Receive Rate: 16384 B/s, 8 pps
========================================
```

### 客户端连接日志
```
New client connected: 192.168.1.100:54321 (ID: 123456)
Client disconnected: ID 123456
Cleaned up 2 expired sessions
```

## 停止服务器

可以通过以下方式停止服务器：
- 按 `Ctrl+C` 发送中断信号
- 发送 SIGTERM 信号（Linux/macOS）
- 关闭命令窗口（Windows）

服务器会关闭：
1. 停止接受新连接
2. 断开所有客户端连接
3. 关闭网络接口
4. 清理资源

## 故障排除

### 常见问题

#### 1. 权限不足
**错误**: `Failed to create TUN interface`
**解决**: 使用管理员权限运行服务器

#### 2. 端口被占用
**错误**: `Failed to bind address: Address already in use`
**解决**: 更改端口号或停止占用端口的程序

#### 3. 配置文件错误
**错误**: `Configuration validation failed`
**解决**: 检查配置文件格式和参数有效性

#### 4. 网络接口创建失败
**错误**: `Failed to create TUN interface`
**解决**: 
- 确保系统支持 TUN/TAP
- 检查内核模块是否加载
- 验证接口名称是否可用

### 调试模式
启用调试模式获取详细日志：
```bash
sudo ./sduvpn-server -c server.json -d
```

### 日志分析
检查日志文件获取详细错误信息：
```bash
# 查看日志文件
tail -f /var/log/sduvpn/server.log

# 查看系统日志
journalctl -u sduvpn-server -f
```

## 性能优化

### 系统配置
1. **网络缓冲区大小**
   ```bash
   # 增加网络缓冲区大小
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   sysctl -p
   ```

2. **文件描述符限制**
   ```bash
   # 增加文件描述符限制
   echo '* soft nofile 65536' >> /etc/security/limits.conf
   echo '* hard nofile 65536' >> /etc/security/limits.conf
   ```

### 配置优化
1. **工作线程数**: 根据 CPU 核心数调整 `worker_threads`
2. **缓冲区大小**: 根据网络带宽调整 `receive_buffer_size` 和 `send_buffer_size`
3. **客户端超时**: 根据网络稳定性调整 `timeout_seconds`

## 安全建议

1. **证书管理**
   - 使用强加密的证书和私钥
   - 定期更新证书
   - 保护私钥文件权限

2. **用户认证**
   - 使用强密码
   - 定期更换密码
   - 限制用户数量

3. **网络安全**
   - 配置防火墙规则
   - 限制访问 IP 范围
   - 监控异常连接

4. **系统安全**
   - 定期更新系统
   - 最小权限原则
   - 审计日志

## 系统服务配置

### Linux Systemd 服务
创建服务文件 `/etc/systemd/system/sduvpn-server.service`：
```ini
[Unit]
Description=SDUVPN Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sduvpn-server -c /etc/sduvpn/server.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启用和启动服务：
```bash
sudo systemctl enable sduvpn-server
sudo systemctl start sduvpn-server
sudo systemctl status sduvpn-server
```

### Windows 服务
可以使用 NSSM 或类似工具将服务器注册为 Windows 服务。

## 网络拓扑示例

```
客户端1 (10.8.0.2) ←→ [互联网] ←→ VPN服务器 (公网IP:1194)
客户端2 (10.8.0.3) ←→ [互联网] ←→     ↓
客户端3 (10.8.0.4) ←→ [互联网] ←→ TUN接口 (10.8.0.1)
                                    ↓
                               内部网络/互联网
```

## 联系和支持

如果您在使用过程中遇到问题，请：
1. 查看日志文件获取错误信息
2. 检查配置文件是否正确
3. 确认系统权限和网络配置
4. 参考故障排除部分

---

**注意**: 本文档基于当前版本的代码编写，具体功能可能随版本更新而变化。请参考最新的代码和文档获取准确信息。
