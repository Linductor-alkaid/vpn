# SDUVPN 测试模块

# =============================================================================
# 测试构建选项
# =============================================================================
option(BUILD_TESTS "Build all tests" ON)

if(NOT BUILD_TESTS)
    message(STATUS "Tests are disabled")
    return()
endif()

# 在Windows平台上禁用依赖GoogleTest的测试
if(WIN32)
    message(STATUS "Building tests (Windows - limited test suite)")
else()
    message(STATUS "Building tests (Full test suite with GoogleTest)")
endif()

# =============================================================================
# 加密库测试
# =============================================================================
if(TARGET sduvpn-crypto)
    # 创建加密库测试可执行文件 (基础测试，不依赖GoogleTest)
    add_executable(test_crypto test_crypto.cpp)
    
    # 以下测试依赖GoogleTest，仅在非Windows平台构建
    if(NOT WIN32)
        # 创建密钥交换测试可执行文件
        add_executable(test_key_exchange test_key_exchange.cpp)
        
        # 创建ECDH性能测试可执行文件
        add_executable(test_ecdh_performance test_ecdh_performance.cpp)
        
        # 创建SHA-256标准测试向量可执行文件
        add_executable(test_sha256_vectors test_sha256_vectors.cpp)
        
        # 创建ECDH安全测试可执行文件
        add_executable(test_ecdh_security test_ecdh_security.cpp)
        
        # 创建ECDH测试向量可执行文件
        add_executable(test_ecdh_vectors test_ecdh_vectors.cpp)
        
        # 创建密钥派生测试向量可执行文件
        add_executable(test_key_derivation_vectors test_key_derivation_vectors.cpp)
        
    endif()
    
    # 链接加密库
    target_link_libraries(test_crypto 
        PRIVATE 
            sduvpn-crypto
    )
    
    # 为非Windows平台的测试链接GoogleTest
    if(NOT WIN32)
        # Linux/Unix平台：链接GoogleTest
        target_link_libraries(test_key_exchange 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        
        target_link_libraries(test_ecdh_performance 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        
        target_link_libraries(test_sha256_vectors 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        
        target_link_libraries(test_ecdh_security 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        
        target_link_libraries(test_ecdh_vectors 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        
        target_link_libraries(test_key_derivation_vectors 
            PRIVATE 
                sduvpn-crypto
                gtest
                gtest_main
        )
        

    endif()
    
    # 设置目标属性
    set_target_properties(test_crypto PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        OUTPUT_NAME "test_crypto"
    )
    
    # 为非Windows平台的测试设置目标属性
    if(NOT WIN32)
        set_target_properties(test_key_exchange PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_key_exchange"
        )
        
        set_target_properties(test_ecdh_performance PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_ecdh_performance"
        )
        
        set_target_properties(test_sha256_vectors PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_sha256_vectors"
        )
        
        set_target_properties(test_ecdh_security PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_ecdh_security"
        )
        
        set_target_properties(test_ecdh_vectors PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_ecdh_vectors"
        )
        
        set_target_properties(test_key_derivation_vectors PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
            OUTPUT_NAME "test_key_derivation_vectors"
        )
        
    endif()
    
    # 包含目录
    target_include_directories(test_crypto 
        PRIVATE 
            ${CMAKE_SOURCE_DIR}/include
    )
    
    # 为非Windows平台的测试设置包含目录
    if(NOT WIN32)
        target_include_directories(test_key_exchange 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
        target_include_directories(test_ecdh_performance 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
        target_include_directories(test_sha256_vectors 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
        target_include_directories(test_ecdh_security 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
        target_include_directories(test_ecdh_vectors 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
        target_include_directories(test_key_derivation_vectors 
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/include
        )
        
    endif()
    
    # Windows 平台特定设置
    if(WIN32)
        # 设置控制台应用程序
        set_target_properties(test_crypto PROPERTIES
            WIN32_EXECUTABLE FALSE
        )
        
        # 使用动态运行时库 (与加密库保持一致)
        if(MSVC)
            target_compile_options(test_crypto PRIVATE 
                $<$<CONFIG:Release>:/MD>
                $<$<CONFIG:Debug>:/MDd>
            )
        endif()
    endif()
    
    # 编译定义
    target_compile_definitions(test_crypto 
        PRIVATE
            SDUVPN_CRYPTO_TEST
    )
    
    # 设置输出目录
    set_target_properties(test_crypto PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/tests
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/tests
    )
    
    message(STATUS "Crypto library test will be built")
else()
    message(WARNING "sduvpn-crypto target not found, skipping crypto tests")
endif()

# =============================================================================
# 服务器组件测试 (仅在非Windows平台编译)
# =============================================================================
if(NOT WIN32)
    # 添加服务器组件测试（需要先编译服务器源文件）
    add_executable(test_server_components test_server_components.cpp)

# 添加服务器源文件（排除main.cpp）
set(SERVER_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/server/server_config.cpp
    ${CMAKE_SOURCE_DIR}/src/server/client_session.cpp
    ${CMAKE_SOURCE_DIR}/src/server/packet_router.cpp
    # 注意：不包含vpn_server.cpp和main.cpp，因为它们包含平台特定代码
)

target_sources(test_server_components PRIVATE ${SERVER_TEST_SOURCES})

# 链接库
target_link_libraries(test_server_components
    PRIVATE
        sduvpn-common
        sduvpn-crypto
        ${THIRD_PARTY_LIBRARIES}
)

# 设置目标属性
set_target_properties(test_server_components PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "test_server_components"
)

# 包含目录
target_include_directories(test_server_components
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

# 编译定义
target_compile_definitions(test_server_components
    PRIVATE
        SDUVPN_SERVER_TEST
        SDUVPN_USE_JSON  # 启用JSON支持用于测试
)

# Windows 平台特定设置
if(WIN32)
    set_target_properties(test_server_components PROPERTIES
        WIN32_EXECUTABLE FALSE
    )
    
    if(MSVC)
        target_compile_options(test_server_components PRIVATE 
            $<$<CONFIG:Release>:/MD>
            $<$<CONFIG:Debug>:/MDd>
        )
    endif()
endif()

# 设置输出目录
set_target_properties(test_server_components PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/tests
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/tests
)

    message(STATUS "Server components test will be built")
else()
    message(STATUS "Server components test disabled on Windows platform")
endif()

# =============================================================================
# 握手测试程序（手动测试，不依赖GoogleTest）
# =============================================================================
add_executable(test_handshake_manual test_handshake_manual.cpp)

# 链接必要的库
target_link_libraries(test_handshake_manual
    PRIVATE
        sduvpn-common
        sduvpn-crypto
)

# 设置目标属性
set_target_properties(test_handshake_manual PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "test_handshake_manual"
)

# 包含目录
target_include_directories(test_handshake_manual
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

# 编译定义
target_compile_definitions(test_handshake_manual
    PRIVATE
        SDUVPN_HANDSHAKE_TEST
)

# Windows 平台特定设置
if(WIN32)
    set_target_properties(test_handshake_manual PROPERTIES
        WIN32_EXECUTABLE FALSE
    )
    
    if(MSVC)
        target_compile_options(test_handshake_manual PRIVATE 
            $<$<CONFIG:Release>:/MD>
            $<$<CONFIG:Debug>:/MDd>
        )
    endif()
endif()

# 设置输出目录
set_target_properties(test_handshake_manual PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/tests
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/tests
)

message(STATUS "Manual handshake test will be built")

# =============================================================================
# 安装配置
# =============================================================================
if(TARGET test_crypto)
    install(TARGETS test_crypto
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/tests
        COMPONENT Tests
    )
endif()

if(TARGET test_server_components)
    install(TARGETS test_server_components
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/tests
        COMPONENT Tests
    )
endif()

if(TARGET test_handshake_manual)
    install(TARGETS test_handshake_manual
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/tests
        COMPONENT Tests
    )
endif()

# =============================================================================
# 测试运行配置 (可选)
# =============================================================================
# 如果启用了 CTest，可以添加测试
if(BUILD_TESTING AND TARGET test_crypto)
    include(CTest)
    add_test(
        NAME CryptoLibraryTest
        COMMAND test_crypto
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests
    )
    
    # 设置测试属性
    set_tests_properties(CryptoLibraryTest PROPERTIES
        TIMEOUT 300  # 5分钟超时
        PASS_REGULAR_EXPRESSION "所有测试通过"
        FAIL_REGULAR_EXPRESSION "部分测试失败"
    )
endif()
