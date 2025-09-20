# ECDH密钥交换使用示例

本文档演示如何使用SDUVPN的ECDH实现进行安全的密钥交换。

## 基本用法

### 1. 密钥对生成

```cpp
#include "crypto/crypto.h"
using namespace sduvpn::crypto;

// 生成Alice的密钥对
uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];

CryptoError result = ECDH::generateKeyPair(alice_private, alice_public);
if (result != CryptoError::SUCCESS) {
    std::cerr << "Failed to generate Alice's key pair" << std::endl;
    return -1;
}

// 生成Bob的密钥对
uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];

result = ECDH::generateKeyPair(bob_private, bob_public);
if (result != CryptoError::SUCCESS) {
    std::cerr << "Failed to generate Bob's key pair" << std::endl;
    return -1;
}
```

### 2. 共享密钥计算

```cpp
// Alice计算共享密钥
uint8_t alice_shared[ECDH_SHARED_SECRET_SIZE];
result = ECDH::computeSharedSecret(alice_private, bob_public, alice_shared);
if (result != CryptoError::SUCCESS) {
    std::cerr << "Failed to compute Alice's shared secret" << std::endl;
    return -1;
}

// Bob计算共享密钥
uint8_t bob_shared[ECDH_SHARED_SECRET_SIZE];
result = ECDH::computeSharedSecret(bob_private, alice_public, bob_shared);
if (result != CryptoError::SUCCESS) {
    std::cerr << "Failed to compute Bob's shared secret" << std::endl;
    return -1;
}

// 验证共享密钥相同
if (memcmp(alice_shared, bob_shared, ECDH_SHARED_SECRET_SIZE) == 0) {
    std::cout << "Key exchange successful!" << std::endl;
} else {
    std::cerr << "Key exchange failed - shared secrets don't match" << std::endl;
    return -1;
}
```

### 3. 完整示例

```cpp
#include "crypto/crypto.h"
#include <iostream>
#include <cstring>

using namespace sduvpn::crypto;

int main() {
    std::cout << "ECDH Key Exchange Example" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // 1. 生成密钥对
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    std::cout << "Generating key pairs..." << std::endl;
    
    if (ECDH::generateKeyPair(alice_private, alice_public) != CryptoError::SUCCESS) {
        std::cerr << "Failed to generate Alice's key pair" << std::endl;
        return -1;
    }
    
    if (ECDH::generateKeyPair(bob_private, bob_public) != CryptoError::SUCCESS) {
        std::cerr << "Failed to generate Bob's key pair" << std::endl;
        return -1;
    }
    
    // 2. 交换公钥（在实际应用中，这通过网络完成）
    std::cout << "Exchanging public keys..." << std::endl;
    std::cout << "Alice's public key: " << utils::toHex(alice_public, ECDH_PUBLIC_KEY_SIZE) << std::endl;
    std::cout << "Bob's public key:   " << utils::toHex(bob_public, ECDH_PUBLIC_KEY_SIZE) << std::endl;
    
    // 3. 计算共享密钥
    std::cout << "Computing shared secrets..." << std::endl;
    
    uint8_t alice_shared[ECDH_SHARED_SECRET_SIZE];
    uint8_t bob_shared[ECDH_SHARED_SECRET_SIZE];
    
    if (ECDH::computeSharedSecret(alice_private, bob_public, alice_shared) != CryptoError::SUCCESS) {
        std::cerr << "Failed to compute Alice's shared secret" << std::endl;
        return -1;
    }
    
    if (ECDH::computeSharedSecret(bob_private, alice_public, bob_shared) != CryptoError::SUCCESS) {
        std::cerr << "Failed to compute Bob's shared secret" << std::endl;
        return -1;
    }
    
    // 4. 验证共享密钥
    std::cout << "Verifying shared secrets..." << std::endl;
    std::cout << "Alice's shared secret: " << utils::toHex(alice_shared, ECDH_SHARED_SECRET_SIZE) << std::endl;
    std::cout << "Bob's shared secret:   " << utils::toHex(bob_shared, ECDH_SHARED_SECRET_SIZE) << std::endl;
    
    if (utils::secureCompare(alice_shared, bob_shared, ECDH_SHARED_SECRET_SIZE)) {
        std::cout << "✓ Key exchange successful! Shared secrets match." << std::endl;
    } else {
        std::cerr << "✗ Key exchange failed! Shared secrets don't match." << std::endl;
        return -1;
    }
    
    // 5. 清理敏感数据
    utils::secureZero(alice_private, sizeof(alice_private));
    utils::secureZero(bob_private, sizeof(bob_private));
    utils::secureZero(alice_shared, sizeof(alice_shared));
    utils::secureZero(bob_shared, sizeof(bob_shared));
    
    std::cout << "Key exchange demonstration completed successfully." << std::endl;
    return 0;
}
```

## 安全注意事项

### 1. 私钥保护

- **永远不要**通过网络传输私钥
- 私钥应该存储在安全的内存中
- 使用完毕后立即清零私钥

```cpp
// 正确的私钥清理
utils::secureZero(private_key, ECDH_PRIVATE_KEY_SIZE);
```

### 2. 公钥验证

我们的实现会自动验证公钥的有效性，防止低阶点攻击：

```cpp
// 自动检查以下攻击：
// - 零点攻击
// - 低阶点攻击 (点1和点p-1)
// - 无效点攻击
```

### 3. 共享密钥使用

共享密钥不应直接用作加密密钥，应使用密钥派生函数（KDF）：

```cpp
// 使用HKDF派生会话密钥
uint8_t session_key[32];
const char* info = "VPN session key";

CryptoError result = KeyDerivation::hkdf(
    shared_secret, ECDH_SHARED_SECRET_SIZE,
    nullptr, 0,  // 无盐值
    reinterpret_cast<const uint8_t*>(info), strlen(info),
    sizeof(session_key),
    session_key
);
```

## 性能特性

### 典型性能指标（在现代x64处理器上）

- **密钥对生成**: ~100-500 微秒
- **共享密钥计算**: ~100-500 微秒
- **内存使用**: 每个密钥对约64字节

### 优化建议

1. **预生成密钥对**: 对于高频应用，可以预生成密钥对池
2. **缓存计算**: 对于重复的密钥交换，可以缓存结果
3. **并行处理**: 密钥交换操作可以并行化

## 错误处理

```cpp
CryptoError result = ECDH::generateKeyPair(private_key, public_key);

switch (result) {
    case CryptoError::SUCCESS:
        // 成功
        break;
    case CryptoError::INVALID_PARAMETER:
        std::cerr << "Invalid parameter provided" << std::endl;
        break;
    case CryptoError::KEY_GENERATION_FAILED:
        std::cerr << "Key generation failed" << std::endl;
        break;
    case CryptoError::RANDOM_GENERATION_FAILED:
        std::cerr << "Random number generation failed" << std::endl;
        break;
    default:
        std::cerr << "Unknown error occurred" << std::endl;
        break;
}
```

## 与VPN协议集成

在SDUVPN中，ECDH被集成到`KeyExchangeProtocol`类中：

```cpp
#include "crypto/key_exchange.h"

// 初始化密钥交换协议
crypto::KeyExchangeProtocol key_exchange;
key_exchange.generateKeyPair();

// 获取本地公钥
uint8_t local_public[ECDH_PUBLIC_KEY_SIZE];
key_exchange.getPublicKey(local_public);

// 设置对方公钥
key_exchange.setPeerPublicKey(peer_public_key);

// 派生会话密钥
key_exchange.deriveSessionKeys();

// 获取会话密钥用于加密
const auto* session_keys = key_exchange.getSessionKeys();
```

这种集成方式提供了更高级的接口，自动处理密钥派生和会话管理。
