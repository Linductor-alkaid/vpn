# SDUVPN 安全修复执行清单

## 🚨 紧急修复任务 (P0 - 2周内)

### ✅ 任务清单

#### 1. 修复密钥交换算法
- [ ] **删除伪ECDH实现**
  - 文件: `src/crypto/key_exchange_protocol.cpp`
  - 行: 143-168
  - 操作: 删除 `computeSharedSecret` 中的简化实现

- [ ] **集成标准Curve25519**
  - 安装libsodium库
  - 创建 `src/crypto/standard_ecdh.cpp`
  - 实现标准ECDH接口
  - 更新CMakeLists.txt依赖

- [ ] **更新密钥交换接口**
  ```cpp
  // 新接口示例
  class StandardECDH {
      CryptoError generateKeyPair();
      CryptoError computeSharedSecret(const uint8_t* peer_key, uint8_t* secret);
  };
  ```

#### 2. 添加握手消息签名验证
- [ ] **实现Ed25519签名**
  - 创建 `src/crypto/digital_signature.cpp`
  - 实现签名和验证函数

- [ ] **修改握手消息结构**
  - 文件: `include/common/secure_protocol.h`
  - 为每个握手消息添加签名字段
  ```cpp
  struct HandshakeInitMessage {
      // 现有字段...
      uint8_t signature[64];        // 新增签名字段
      uint64_t timestamp;           // 新增时间戳
  };
  ```

- [ ] **更新握手流程**
  - 文件: `src/common/secure_protocol.cpp`
  - 在发送前签名消息
  - 在接收后验证签名

## 🟠 高危修复任务 (P1 - 4周内)

### ✅ 任务清单

#### 3. 修复密码处理
- [ ] **移除明文密码传输**
  - 文件: `src/client/linux/linux_vpn_client.cpp:514-516`
  - 文件: `src/client/windows/windows_vpn_client.cpp:369-371`
  - 实现SRP协议替代明文认证

- [ ] **加强密码存储加密**
  - 文件: `src/common/config_manager.cpp:219-233`
  - 替换XOR加密为Argon2哈希
  - 实现安全的密码验证器

#### 4. 加强序列号验证
- [ ] **减小重排序窗口**
  - 文件: `src/common/secure_protocol.cpp:557`
  - 将 `MAX_OUT_OF_ORDER` 从64改为16

- [ ] **添加时间戳验证**
  - 实现消息时间戳检查
  - 添加时间窗口容忍度配置

## 🟡 中危修复任务 (P2 - 6周内)

### ✅ 任务清单

#### 5. 修复IV生成
- [ ] **使用安全随机数**
  - 文件: `src/common/secure_protocol.cpp:290-309`
  - 替换可预测的IV生成逻辑
  ```cpp
  void SecureMessage::generateIV(uint8_t* iv) const {
      crypto::SecureRandom::generate(iv, crypto::AES_GCM_IV_SIZE);
  }
  ```

#### 6. 加密配置信息
- [ ] **修复配置加密**
  - 文件: `src/common/secure_protocol.cpp:424-426`
  - 实现真正的配置信息加密
  - 使用会话密钥加密配置数据

#### 7. 实现时间戳验证
- [ ] **添加消息时间戳**
  - 为所有消息类型添加时间戳字段
  - 实现时间窗口验证逻辑

## 🟢 低危修复任务 (P3 - 8周内)

### ✅ 任务清单

#### 8. 清理调试信息
- [ ] **移除敏感信息输出**
  - 文件: `src/crypto/key_exchange_protocol.cpp:117-119`
  - 删除或条件化密钥输出语句

- [ ] **实现安全日志**
  - 创建分级日志系统
  - 实现敏感信息脱敏

## 🔧 具体修复代码示例

### 1. 标准ECDH实现

```cpp
// src/crypto/standard_ecdh.cpp
#include <sodium.h>

class StandardECDH {
private:
    uint8_t private_key_[crypto_scalarmult_curve25519_SCALARBYTES];
    uint8_t public_key_[crypto_scalarmult_curve25519_BYTES];

public:
    CryptoError generateKeyPair() {
        crypto_scalarmult_curve25519_base(public_key_, private_key_);
        return CryptoError::SUCCESS;
    }
    
    CryptoError computeSharedSecret(const uint8_t* peer_public_key, uint8_t* shared_secret) {
        if (crypto_scalarmult_curve25519(shared_secret, private_key_, peer_public_key) != 0) {
            return CryptoError::KEY_GENERATION_FAILED;
        }
        return CryptoError::SUCCESS;
    }
};
```

### 2. 安全IV生成

```cpp
// 修复 src/common/secure_protocol.cpp
void SecureMessage::generateIV(uint8_t* iv) const {
    // 使用加密安全的随机数生成器
    crypto::CryptoError result = crypto::SecureRandom::generate(iv, crypto::AES_GCM_IV_SIZE);
    if (result != crypto::CryptoError::SUCCESS) {
        throw std::runtime_error("Failed to generate secure IV");
    }
}
```

### 3. 序列号窗口修复

```cpp
// 修复 src/common/secure_protocol.cpp
bool SecureProtocolContext::validateSequence(uint32_t sequence) {
    const uint32_t MAX_OUT_OF_ORDER = 16;  // 减小窗口
    const uint32_t MAX_TIME_DIFF = 30;     // 30秒时间窗口
    
    // 添加时间检查
    uint64_t current_time = getCurrentTimestamp();
    if (current_time - last_message_time_ > MAX_TIME_DIFF * 1000) {
        return false;  // 消息过期
    }
    
    if (sequence >= expected_sequence_ && sequence < expected_sequence_ + MAX_OUT_OF_ORDER) {
        expected_sequence_ = sequence + 1;
        last_message_time_ = current_time;
        return true;
    }
    
    return false;
}
```

### 4. 签名验证实现

```cpp
// 新增 src/crypto/digital_signature.cpp
class Ed25519Signature {
public:
    static CryptoError sign(const uint8_t* private_key, 
                           const uint8_t* message, size_t message_len,
                           uint8_t* signature) {
        crypto_sign_detached(signature, nullptr, message, message_len, private_key);
        return CryptoError::SUCCESS;
    }
    
    static CryptoError verify(const uint8_t* public_key,
                             const uint8_t* message, size_t message_len,
                             const uint8_t* signature) {
        if (crypto_sign_verify_detached(signature, message, message_len, public_key) != 0) {
            return CryptoError::AUTHENTICATION_FAILED;
        }
        return CryptoError::SUCCESS;
    }
};
```

## 📋 验证清单

每完成一个任务后，请验证：

### 功能验证
- [ ] 编译通过无警告
- [ ] 单元测试全部通过
- [ ] 集成测试正常
- [ ] 性能无明显退化

### 安全验证
- [ ] 静态代码分析通过
- [ ] 安全测试用例通过
- [ ] 代码审查完成
- [ ] 文档更新完成

## 🚀 快速开始

1. **环境准备**
   ```bash
   # 安装libsodium
   sudo apt-get install libsodium-dev  # Ubuntu/Debian
   # 或
   brew install libsodium              # macOS
   ```

2. **创建新分支**
   ```bash
   git checkout -b security-fixes
   ```

3. **开始修复**
   - 按优先级P0 -> P1 -> P2 -> P3顺序进行
   - 每完成一个任务提交一次代码
   - 及时更新此清单的完成状态

4. **测试验证**
   ```bash
   # 编译测试
   mkdir build && cd build
   cmake .. && make
   
   # 运行安全测试
   ./test_handshake_manual
   ./test_crypto
   ```

## 📞 遇到问题？

如果在执行过程中遇到技术问题：

1. **查看详细文档**: `docs/security-improvement-plan.md`
2. **联系安全团队**: security@sduvpn.org
3. **创建Issue**: 在项目仓库中创建技术问题Issue

---
**最后更新**: 2025-09-20  
**负责人**: 安全团队  
**状态**: 待执行
