# SDUVPN - 跨平台VPN解决方案

## 项目概述

SDUVPN是一个基于C++17开发的跨平台VPN解决方案，旨在为多设备提供安全的虚拟局域网连接。

### 支持平台
- **服务器**: Ubuntu 20.04+
- **客户端**: Windows 10/11, Android 7.0+

### 核心特性
- 🔐 自研加密库(AES-256-GCM + ECDH)
- 🌐 跨平台虚拟网卡支持
- ⚡ 高性能异步网络I/O
- 🛡️ 内存安全设计
- 📱 移动端适配

## 快速开始

### 1. 下载第三方库

**Windows用户**:
```batch
# 运行依赖下载脚本
scripts\setup_dependencies.bat
```

**Linux用户**:
```bash
# 运行依赖下载脚本
chmod +x scripts/setup_dependencies.sh
./scripts/setup_dependencies.sh
```

**手动下载** (如果脚本失败):

| 库名称 | 项目地址 | 版本 | 用途 |
|--------|----------|------|------|
| nlohmann/json | https://github.com/nlohmann/json | v3.11.2 | JSON解析 |
| spdlog | https://github.com/gabime/spdlog | v1.12.0 | 日志记录 |
| GoogleTest | https://github.com/google/googletest | v1.14.0 | 单元测试 |
| Asio | https://github.com/chriskohlhoff/asio | asio-1-28-0 | 网络I/O |

### 2. 构建项目

**Windows (Visual Studio)**:
```batch
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

**Linux**:
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 3. 运行测试

```bash
cd build
ctest --config Release
```

## 项目结构

```
sduvpn/
├── src/                    # 源代码
│   ├── common/            # 公共模块
│   ├── server/            # 服务器端(Linux)
│   ├── client/            # 客户端
│   │   ├── windows/       # Windows客户端
│   │   └── android/       # Android客户端
│   └── crypto/            # 自研加密库
├── include/               # 头文件
├── third_party/          # 第三方库
├── tests/                # 测试代码
├── config/               # 配置文件
├── docs/                 # 文档
└── scripts/              # 构建脚本
```

## 开发进度

- [x] 项目架构设计
- [x] 第三方库集成
- [x] 自研加密库框架
- [ ] 服务器核心实现
- [ ] Windows客户端
- [ ] Android客户端
- [ ] 系统测试

## 技术栈

### 核心技术
- **语言**: C++17
- **构建**: CMake 3.16+
- **网络**: Asio (异步I/O)
- **加密**: 自研加密库
- **日志**: spdlog
- **测试**: GoogleTest

### 平台特定
- **Linux**: TUN/TAP接口
- **Windows**: TAP-Windows驱动
- **Android**: VpnService API + JNI

## 安全特性

### 加密算法
- **对称加密**: AES-256-GCM
- **密钥交换**: ECDH (Curve25519)
- **哈希算法**: SHA-256
- **密钥派生**: PBKDF2/HKDF

### 安全措施
- 内存安全(安全缓冲区)
- 常时间比较(防时序攻击)
- 完美前向保密
- 数据完整性校验

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件

## 联系方式

- 项目主页: [GitHub仓库地址]
- 问题报告: [Issues页面]
- 开发文档: [docs/](docs/)

---

*SDUVPN Team - 构建安全可靠的网络连接*
