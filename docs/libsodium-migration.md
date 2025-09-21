# libsodium 集成方式迁移说明

## 变更概述

本项目已将 libsodium 的集成方式从第三方库源码包含改为系统安装或包管理器安装。这一变更提高了项目的可维护性和安全性。

## 变更详情

### 1. 移除的内容

#### CMakeLists.txt
- ✅ 移除了 `third_party/libsodium` 目录检查
- ✅ 移除了 libsodium 源码编译配置
- ✅ 更新为优先使用 vcpkg 安装的版本
- ✅ 添加了详细的错误提示和文档引用

#### scripts/setup_dependencies.bat
- ✅ 移除了 libsodium 的 Git 克隆下载
- ✅ 添加了安装提示信息
- ✅ 更新了库列表显示

#### scripts/setup_dependencies.sh (新增)
- ✅ 创建了 Linux 版本的依赖安装脚本
- ✅ 包含了 libsodium 安装提示

### 2. 新增的内容

#### docs/libsodium-installation.md (新增)
完整的 libsodium 安装指南，包含：
- Windows 平台安装方法（vcpkg、预编译二进制、源码编译）
- Linux 平台安装方法（apt、yum、dnf、pacman、源码编译）
- macOS 平台安装方法（Homebrew、MacPorts）
- CMake 集成说明
- 故障排除指南
- 安全注意事项

#### 更新的文档
- ✅ README.md - 添加了 libsodium 安装步骤
- ✅ PROJECT_SUMMARY.md - 记录了构建系统变更
- ✅ docs/libsodium-migration.md - 本迁移说明文档

### 3. 配置变更

#### 新的 CMake 查找逻辑
1. **优先级 1**: vcpkg 安装的 libsodium（Windows 推荐）
   ```cmake
   find_package(unofficial-sodium CONFIG QUIET)
   ```

2. **优先级 2**: 系统安装的 libsodium（Linux/macOS 推荐）
   ```cmake
   pkg_check_modules(SODIUM QUIET libsodium)
   ```

3. **错误处理**: 找不到时显示详细错误信息并引用文档

## 迁移指南

### 对于开发者

#### Windows 开发者
```batch
# 1. 安装 vcpkg（如果尚未安装）
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# 2. 安装 libsodium
.\vcpkg install libsodium:x64-windows

# 3. 使用 vcpkg 工具链配置项目
cmake -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg路径]/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

#### Linux 开发者
```bash
# 1. 安装 libsodium 开发包
sudo apt install libsodium-dev  # Ubuntu/Debian
# 或
sudo yum install libsodium-devel  # CentOS/RHEL

# 2. 正常配置项目
cmake -B build -DCMAKE_BUILD_TYPE=Release
make -C build -j$(nproc)
```

#### macOS 开发者
```bash
# 1. 安装 libsodium
brew install libsodium

# 2. 正常配置项目
cmake -B build -DCMAKE_BUILD_TYPE=Release
make -C build -j$(nproc)
```

### 对于 CI/CD

#### GitHub Actions 示例
```yaml
# Windows
- name: Install libsodium (Windows)
  run: |
    vcpkg install libsodium:x64-windows
  
- name: Configure (Windows)
  run: |
    cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake

# Linux
- name: Install libsodium (Linux)
  run: |
    sudo apt update
    sudo apt install libsodium-dev

- name: Configure (Linux)
  run: |
    cmake -B build -DCMAKE_BUILD_TYPE=Release
```

## 变更优势

### 1. 安全性提升
- 使用官方维护的软件包，及时获取安全更新
- 减少了源码依赖，降低了供应链攻击风险

### 2. 维护性改善
- 不再需要维护 libsodium 的源码副本
- 减少了项目体积和复杂度
- 简化了第三方库管理

### 3. 兼容性增强
- 支持系统包管理器安装的版本
- 与系统其他软件的 libsodium 依赖共享
- 更好的平台集成

### 4. 构建效率
- 减少了编译时间（不需要重新编译 libsodium）
- 利用预编译的优化版本

## 常见问题

### Q: 为什么不再支持 third_party 方式？
A: 主要原因包括：
- 安全性：系统包管理器提供及时的安全更新
- 维护负担：减少了维护第三方库源码的工作量
- 标准化：遵循现代 C++ 项目的最佳实践

### Q: 如何处理不同版本的兼容性？
A: 项目要求 libsodium 1.0.18+，大多数现代系统的包管理器都提供兼容版本。

### Q: 离线环境如何处理？
A: 可以使用预编译的二进制文件或在有网络的环境中预先安装。

### Q: 如何回退到旧版本？
A: 可以使用 Git 回退到变更前的提交，但不建议这样做。

## 相关链接

- [libsodium 安装指南](libsodium-installation.md)
- [libsodium 官方网站](https://libsodium.org/)
- [vcpkg 官方文档](https://vcpkg.io/)

---

*更新日期: 2025年9月20日*
