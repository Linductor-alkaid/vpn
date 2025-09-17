#include "crypto/crypto.h"
#include <cstring>
#include <new>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace sduvpn {
namespace crypto {

SecureBuffer::SecureBuffer(size_t size) : data_(nullptr), size_(size) {
    if (size == 0) {
        return;
    }
    
#ifdef _WIN32
    // Windows: 使用VirtualAlloc分配可锁定的内存
    data_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 
        size, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    ));
    
    if (data_ != nullptr) {
        // 锁定内存页，防止交换到磁盘
        VirtualLock(data_, size);
    }
#else
    // Linux: 使用mmap分配内存
    data_ = static_cast<uint8_t*>(mmap(
        nullptr,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    ));
    
    if (data_ != MAP_FAILED) {
        // 锁定内存页，防止交换到磁盘
        mlock(data_, size);
    } else {
        data_ = nullptr;
    }
#endif
    
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
}

SecureBuffer::~SecureBuffer() {
    if (data_ != nullptr && size_ > 0) {
        // 安全清零
        clear();
        
#ifdef _WIN32
        VirtualUnlock(data_, size_);
        VirtualFree(data_, 0, MEM_RELEASE);
#else
        munlock(data_, size_);
        munmap(data_, size_);
#endif
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept 
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // 清理当前资源
        if (data_ != nullptr && size_ > 0) {
            clear();
#ifdef _WIN32
            VirtualUnlock(data_, size_);
            VirtualFree(data_, 0, MEM_RELEASE);
#else
            munlock(data_, size_);
            munmap(data_, size_);
#endif
        }
        
        // 移动资源
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void SecureBuffer::clear() {
    if (data_ != nullptr && size_ > 0) {
        utils::secureZero(data_, size_);
    }
}

} // namespace crypto
} // namespace sduvpn
