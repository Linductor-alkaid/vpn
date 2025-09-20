# SDUVPN 加密库构建配置

# =============================================================================
# 加密库源文件 (只包含已实现的文件)
# =============================================================================
set(CRYPTO_SOURCES
    secure_buffer.cpp
    secure_random.cpp
    crypto_utils.cpp
    crypto_context.cpp
    aes256gcm.cpp
    ecdh.cpp
    key_derivation.cpp
    sha256.cpp
    key_exchange_protocol.cpp
)

# =============================================================================
# 创建加密库
# =============================================================================
add_library(sduvpn-crypto STATIC ${CRYPTO_SOURCES})

# 设置目标属性
set_target_properties(sduvpn-crypto PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# 包含目录
target_include_directories(sduvpn-crypto 
    PUBLIC 
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 链接第三方库
target_link_libraries(sduvpn-crypto 
    PRIVATE 
        ${THIRD_PARTY_LIBRARIES}
)

# 平台特定链接库
if(WIN32)
    # Windows平台使用CryptoAPI
    target_link_libraries(sduvpn-crypto 
        PRIVATE 
            advapi32    # CryptGenRandom
            bcrypt      # Windows Cryptography API
    )
elseif(UNIX)
    # Linux平台
    target_link_libraries(sduvpn-crypto 
        PRIVATE 
            ${CMAKE_DL_LIBS}
    )
endif()

# 编译定义
target_compile_definitions(sduvpn-crypto 
    PRIVATE
        SDUVPN_CRYPTO_IMPLEMENTATION
)

# 导出符号 (Windows)
if(WIN32 AND BUILD_SHARED_LIBS)
    target_compile_definitions(sduvpn-crypto 
        PRIVATE 
            SDUVPN_CRYPTO_EXPORT
        INTERFACE 
            SDUVPN_CRYPTO_IMPORT
    )
endif()

# =============================================================================
# 安装配置
# =============================================================================
install(TARGETS sduvpn-crypto
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/crypto/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sduvpn/crypto
    FILES_MATCHING PATTERN "*.h"
)
