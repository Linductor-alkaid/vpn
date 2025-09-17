#include "crypto/crypto.h"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <cstring>
#endif

namespace sduvpn {
namespace crypto {
namespace utils {

bool secureCompare(const uint8_t* a, const uint8_t* b, size_t len) {
    if (a == nullptr || b == nullptr) {
        return false;
    }
    
    // 使用常时间比较算法，防止时序攻击
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}

void secureZero(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) {
        return;
    }
    
#ifdef _WIN32
    // Windows: 使用SecureZeroMemory，编译器不会优化掉
    SecureZeroMemory(ptr, len);
#else
    // Linux: 使用volatile防止编译器优化
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
    
    // 额外的内存屏障
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

std::string toHex(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return "";
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    
    return oss.str();
}

size_t fromHex(const std::string& hex, uint8_t* data, size_t max_len) {
    if (hex.empty() || data == nullptr || max_len == 0) {
        return 0;
    }
    
    // 检查字符串长度必须是偶数
    if (hex.length() % 2 != 0) {
        return 0;
    }
    
    size_t byte_len = hex.length() / 2;
    if (byte_len > max_len) {
        return 0;
    }
    
    // 转换十六进制字符串
    for (size_t i = 0; i < byte_len; ++i) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        
        // 检查字符是否为有效的十六进制
        if (!std::isxdigit(high) || !std::isxdigit(low)) {
            return 0;
        }
        
        // 转换字符到数值
        auto hexToValue = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        
        data[i] = (hexToValue(high) << 4) | hexToValue(low);
    }
    
    return byte_len;
}

} // namespace utils
} // namespace crypto
} // namespace sduvpn
