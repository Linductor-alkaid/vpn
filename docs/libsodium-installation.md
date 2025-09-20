# libsodium 安装指南

本文档提供了在不同操作系统上安装 libsodium 加密库的详细说明。

## 概述

libsodium 是一个现代化、易于使用的软件库，用于加密、解密、签名、密码哈希等操作。本项目使用 libsodium 来实现各种加密功能。

**重要提示**: 本项目不再将 libsodium 作为第三方库包含在源码中，而是依赖系统安装或包管理器安装的版本。

## Windows 平台安装

### 方法 1: 使用 vcpkg（推荐）

1. **安装 vcpkg**
   ```powershell
   # 克隆 vcpkg
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   
   # 运行引导脚本
   .\bootstrap-vcpkg.bat
   
   # 集成到 Visual Studio
   .\vcpkg integrate install
   ```

2. **安装 libsodium**
   ```powershell
   # 安装 x64 版本
   .\vcpkg install libsodium:x64-windows
   
   # 或者安装 x86 版本
   .\vcpkg install libsodium:x86-windows
   ```

3. **配置 CMake 项目**
   ```powershell
   # 在项目根目录下，使用 vcpkg 工具链配置项目
   cmake -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg根目录]/scripts/buildsystems/vcpkg.cmake
   
   # 编译项目
   cmake --build build --config Release
   ```

### 方法 2: 使用预编译二进制文件

1. 从 [libsodium 发布页面](https://github.com/jedisct1/libsodium/releases) 下载预编译的 Windows 二进制文件
2. 解压到合适的目录（例如 `C:\libsodium`）
3. 配置 CMake 时指定路径：
   ```powershell
   cmake -B build -DLIBSODIUM_ROOT_DIR=C:\libsodium
   ```

### 方法 3: 从源码编译

1. **安装依赖**
   - Visual Studio 2019 或更新版本
   - CMake 3.16 或更新版本

2. **编译步骤**
   ```powershell
   git clone https://github.com/jedisct1/libsodium.git
   cd libsodium
   mkdir build
   cd build
   cmake .. -DCMAKE_INSTALL_PREFIX=C:\libsodium
   cmake --build . --config Release
   cmake --install . --config Release
   ```

## Linux 平台安装

### 方法 1: 使用包管理器（推荐）

#### Ubuntu/Debian
```bash
# 更新包列表
sudo apt update

# 安装 libsodium 开发包
sudo apt install libsodium-dev

# 验证安装
pkg-config --modversion libsodium
```

#### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install libsodium-devel

# Fedora
sudo dnf install libsodium-devel

# 验证安装
pkg-config --modversion libsodium
```

#### Arch Linux
```bash
# 安装 libsodium
sudo pacman -S libsodium

# 验证安装
pkg-config --modversion libsodium
```

### 方法 2: 从源码编译

```bash
# 安装编译依赖
sudo apt install build-essential cmake

# 克隆源码
git clone https://github.com/jedisct1/libsodium.git
cd libsodium

# 编译安装
./configure
make && make check
sudo make install

# 更新动态库缓存
sudo ldconfig
```

## macOS 平台安装

### 使用 Homebrew
```bash
# 安装 Homebrew（如果尚未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 libsodium
brew install libsodium

# 验证安装
pkg-config --modversion libsodium
```

### 使用 MacPorts
```bash
# 安装 libsodium
sudo port install libsodium

# 验证安装
pkg-config --modversion libsodium
```

## CMake 集成

本项目的 CMakeLists.txt 已经配置了多种 libsodium 查找方式：

1. **vcpkg 安装的版本**（Windows 推荐）
2. **系统包管理器安装的版本**（Linux/macOS 推荐）
3. **手动指定路径的版本**

### 配置示例

```bash
# 使用 vcpkg（Windows）
cmake -B build -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg/scripts/buildsystems/vcpkg.cmake

# 使用系统安装的版本（Linux/macOS）
cmake -B build

# 手动指定 libsodium 路径
cmake -B build -DLIBSODIUM_ROOT_DIR=/path/to/libsodium
```

## 验证安装

编译项目后，可以运行以下命令验证 libsodium 是否正确链接：

```bash
# Windows
.\build\bin\sduvpn-client.exe --version

# Linux/macOS
./build/bin/sduvpn-client --version
```

## 故障排除

### Windows 常见问题

1. **找不到 libsodium**
   - 确保使用了正确的 vcpkg 工具链文件
   - 检查 vcpkg 是否正确安装了 libsodium

2. **链接错误**
   - 确保目标架构匹配（x64 vs x86）
   - 重新运行 `vcpkg integrate install`

### Linux 常见问题

1. **找不到 libsodium**
   ```bash
   # 检查是否安装了开发包
   dpkg -l | grep libsodium
   
   # 安装开发包
   sudo apt install libsodium-dev
   ```

2. **pkg-config 找不到 libsodium**
   ```bash
   # 检查 pkg-config 路径
   export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
   ```

## 版本要求

- **最低版本**: libsodium 1.0.18
- **推荐版本**: libsodium 1.0.19 或更新版本
- **测试版本**: libsodium 1.0.20

## 安全注意事项

1. **始终使用官方源**：只从官方 GitHub 仓库或可信的包管理器安装 libsodium
2. **验证完整性**：在生产环境中，建议验证下载文件的 GPG 签名
3. **定期更新**：保持 libsodium 版本更新，及时获取安全修复

## 许可证

libsodium 使用 ISC 许可证，这是一个宽松的开源许可证，允许商业使用。

## 相关链接

- [libsodium 官方网站](https://libsodium.org/)
- [libsodium GitHub 仓库](https://github.com/jedisct1/libsodium)
- [libsodium 文档](https://doc.libsodium.org/)
- [vcpkg 官方网站](https://vcpkg.io/)
