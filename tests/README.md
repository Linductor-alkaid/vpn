# SDUVPN 测试模块

## 概述

本目录包含 SDUVPN 项目的测试程序，专门为 Windows 环境设计，无需依赖 GoogleTest 和 spdlog 等可能在 Windows 上出现编译问题的第三方库。

## 测试内容

### test_crypto.cpp
加密库功能测试，包含：

#### SecureRandom 测试
- **基础功能测试**: 验证不同长度随机数生成
- **唯一性测试**: 确保生成的随机数不重复
- **整数生成测试**: 验证指定范围内的随机整数生成

#### SecureBuffer 测试
- **基础功能测试**: 验证安全内存分配和访问
- **清零功能测试**: 验证敏感数据安全清除
- **移动语义测试**: 验证 C++ 移动语义正确实现

#### 工具函数测试
- **安全比较函数**: 验证常时间比较算法
- **十六进制转换**: 验证二进制与十六进制字符串互转
- **安全清零**: 验证内存安全清除功能

#### 性能测试
- **随机数生成性能**: 测量大批量随机数生成的吞吐量

## 构建和运行

### 前置条件
- Windows 10/11
- Visual Studio 2019 或更新版本
- CMake 3.16 或更新版本

### 构建步骤

1. **生成构建文件**
   ```powershell
   cd G:\myproject\sduvpn
   mkdir build
   cd build
   cmake ..
   ```

2. **编译项目**
   ```powershell
   cmake --build . --config Release
   ```

3. **运行测试**
   ```powershell
   # 运行加密库测试
   .\bin\tests\test_crypto.exe
   ```

### 构建选项

- `BUILD_TESTS=ON/OFF`: 是否构建测试 (默认: ON)
- `CMAKE_BUILD_TYPE=Release/Debug`: 构建类型 (默认: Release)

示例：
```powershell
cmake .. -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Release
```

## 输出解释

### 成功输出示例
```
=== SDUVPN 加密库测试程序 ===
Windows 平台 - 无依赖版本
编译时间: Dec 17 2024 14:30:25

[测试] SecureRandom 基础功能 ... 通过
[测试] SecureRandom 唯一性 ... 通过
[测试] SecureBuffer 基础功能 ... 通过
...

=== 测试总结 ===
总计: 10 个测试
通过: 10 个
失败: 0 个
成功率: 100.0%

🎉 所有测试通过！加密库工作正常。
```

### 失败输出示例
```
[测试] SecureRandom 基础功能 ... 失败
生成 32 字节随机数失败

=== 测试总结 ===
总计: 10 个测试
通过: 9 个
失败: 1 个
成功率: 90.0%

❌ 部分测试失败，请检查实现。
```

## 故障排除

### 常见问题

1. **链接错误**: 确保已正确构建 sduvpn_crypto 库
2. **权限问题**: 在 Windows 上可能需要管理员权限进行内存锁定操作
3. **性能问题**: 如果性能测试超时，可能是系统资源不足

### 调试建议

1. 使用 Debug 构建获取更多信息：
   ```powershell
   cmake .. -DCMAKE_BUILD_TYPE=Debug
   ```

2. 检查具体的测试输出，每个测试都会显示详细的执行过程

3. 如果随机数生成失败，检查 Windows Cryptography API 是否可用

## 扩展测试

要添加新的测试：

1. 在 `test_crypto.cpp` 中创建新的测试函数
2. 在 `main()` 函数中使用 `SimpleTest::run()` 注册测试
3. 重新编译并运行

测试函数示例：
```cpp
bool testNewFeature() {
    std::cout << "\n--- 新功能测试 ---" << std::endl;
    
    // 测试逻辑
    bool result = /* 测试代码 */;
    
    if (result) {
        std::cout << "✓ 新功能工作正常" << std::endl;
        return true;
    } else {
        std::cout << "✗ 新功能测试失败" << std::endl;
        return false;
    }
}
```

## 注意事项

- 本测试程序专为 Windows 环境优化，避免了 pthread 依赖问题
- 测试使用静态链接，减少运行时依赖
- 性能测试结果可能因系统配置而异
- 安全功能测试可能需要足够的系统权限
