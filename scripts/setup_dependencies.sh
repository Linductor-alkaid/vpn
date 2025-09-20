#!/bin/bash

# 设置第三方依赖库脚本 (Linux)
# 此脚本会下载项目所需的第三方库

set -e  # 遇到错误时退出

echo "正在设置第三方依赖..."
echo

# 切换到项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# 创建 third_party 目录
echo "创建 third_party 目录..."
mkdir -p third_party
cd third_party

echo
echo "[1/4] 下载 nlohmann/json..."
if [ -d "json" ]; then
    echo "json 目录已存在，跳过下载"
else
    if git clone https://github.com/nlohmann/json.git json; then
        cd json
        git checkout v3.11.2
        cd ..
        echo "✓ nlohmann/json 下载完成"
    else
        echo "✗ nlohmann/json 下载失败"
        exit 1
    fi
fi

echo
echo "[2/4] 下载 spdlog..."
if [ -d "spdlog" ]; then
    echo "spdlog 目录已存在，跳过下载"
else
    if git clone https://github.com/gabime/spdlog.git spdlog; then
        cd spdlog
        git checkout v1.12.0
        cd ..
        echo "✓ spdlog 下载完成"
    else
        echo "✗ spdlog 下载失败"
        exit 1
    fi
fi

echo
echo "[3/4] 下载 GoogleTest..."
if [ -d "googletest" ]; then
    echo "googletest 目录已存在，跳过下载"
else
    if git clone https://github.com/google/googletest.git googletest; then
        cd googletest
        git checkout v1.14.0
        cd ..
        echo "✓ GoogleTest 下载完成"
    else
        echo "✗ GoogleTest 下载失败"
        exit 1
    fi
fi

echo
echo "[4/4] 下载 Asio..."
if [ -d "asio" ]; then
    echo "asio 目录已存在，跳过下载"
else
    if git clone https://github.com/chriskohlhoff/asio.git asio; then
        cd asio
        git checkout asio-1-28-0
        cd ..
        echo "✓ Asio 下载完成"
    else
        echo "✗ Asio 下载失败"
        exit 1
    fi
fi

echo
echo "[5/5] libsodium 安装提示..."
echo
echo "⚠️  注意: 本项目不再将 libsodium 作为第三方库下载"
echo "   请使用以下方式安装 libsodium:"
echo
echo "   Ubuntu/Debian: sudo apt install libsodium-dev"
echo "   CentOS/RHEL:   sudo yum install libsodium-devel"
echo "   Fedora:        sudo dnf install libsodium-devel"
echo "   Arch Linux:    sudo pacman -S libsodium"
echo
echo "   详细安装说明请参阅: docs/libsodium-installation.md"
echo

echo
echo "========================================"
echo "第三方库下载完成！"
echo "========================================"
echo
echo "下载的库："
[ -d "json" ] && echo "✓ nlohmann/json (v3.11.2)"
[ -d "spdlog" ] && echo "✓ spdlog (v1.12.0)"
[ -d "googletest" ] && echo "✓ GoogleTest (v1.14.0)"
[ -d "asio" ] && echo "✓ Asio (v1.28.0)"
echo
echo "需要单独安装的库："
echo "  libsodium - 请参阅 docs/libsodium-installation.md"
echo
echo "接下来请先安装 libsodium，然后运行 cmake 配置项目"
