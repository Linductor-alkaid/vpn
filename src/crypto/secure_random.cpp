#include "crypto/crypto.h"
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#else
#include <fstream>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace sduvpn {
namespace crypto {

CryptoError SecureRandom::generate(uint8_t* buffer, size_t size) {
    if (buffer == nullptr || size == 0) {
        return CryptoError::INVALID_PARAMETER;
    }
    
#ifdef _WIN32
    // Windows: 优先使用BCryptGenRandom (Windows Vista+)
    NTSTATUS status = BCryptGenRandom(
        nullptr,                    // 使用默认算法提供程序
        buffer,
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    
    if (NT_SUCCESS(status)) {
        return CryptoError::SUCCESS;
    }
    
    // 回退到CryptGenRandom
    HCRYPTPROV hCryptProv = 0;
    if (CryptAcquireContext(&hCryptProv, nullptr, nullptr, 
                           PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BOOL result = CryptGenRandom(hCryptProv, 
                                   static_cast<DWORD>(size), buffer);
        CryptReleaseContext(hCryptProv, 0);
        
        if (result) {
            return CryptoError::SUCCESS;
        }
    }
    
#else
    // Linux: 优先使用getrandom系统调用
    #ifdef __linux__
    ssize_t result = getrandom(buffer, size, 0);
    if (result == static_cast<ssize_t>(size)) {
        return CryptoError::SUCCESS;
    }
    #endif
    
    // 回退到/dev/urandom
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.is_open()) {
        urandom.read(reinterpret_cast<char*>(buffer), size);
        if (urandom.gcount() == static_cast<std::streamsize>(size)) {
            return CryptoError::SUCCESS;
        }
    }
    
    // 最后回退到/dev/random (可能会阻塞)
    std::ifstream random_dev("/dev/random", std::ios::binary);
    if (random_dev.is_open()) {
        random_dev.read(reinterpret_cast<char*>(buffer), size);
        if (random_dev.gcount() == static_cast<std::streamsize>(size)) {
            return CryptoError::SUCCESS;
        }
    }
#endif
    
    // 所有方法都失败，使用C++标准库作为最后手段
    // 注意：这不如系统提供的随机数生成器安全
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    static thread_local std::uniform_int_distribution<unsigned int> dis(0, 255);
    
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return CryptoError::SUCCESS;
}

uint32_t SecureRandom::generateInt(uint32_t min, uint32_t max) {
    if (min >= max) {
        return min;
    }
    
    uint32_t range = max - min + 1;
    uint32_t random_bytes = 0;
    
    // 生成4字节随机数
    if (generate(reinterpret_cast<uint8_t*>(&random_bytes), 
                sizeof(random_bytes)) != CryptoError::SUCCESS) {
        // 回退到标准库
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis(min, max);
        return dis(gen);
    }
    
    // 使用模运算，但要避免模偏差
    // 使用拒绝采样确保均匀分布
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    
    while (random_bytes >= limit) {
        if (generate(reinterpret_cast<uint8_t*>(&random_bytes), 
                    sizeof(random_bytes)) != CryptoError::SUCCESS) {
            break;
        }
    }
    
    return min + (random_bytes % range);
}

} // namespace crypto
} // namespace sduvpn
