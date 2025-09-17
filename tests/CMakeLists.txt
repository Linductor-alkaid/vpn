# SDUVPN 测试模块

# =============================================================================
# 测试构建选项
# =============================================================================
option(BUILD_TESTS "Build all tests" ON)

if(NOT BUILD_TESTS)
    message(STATUS "Tests are disabled")
    return()
endif()

message(STATUS "Building tests")

# =============================================================================
# 加密库测试
# =============================================================================
if(TARGET sduvpn_crypto)
    # 创建加密库测试可执行文件
    add_executable(test_crypto test_crypto.cpp)
    
    # 链接加密库
    target_link_libraries(test_crypto 
        PRIVATE 
            sduvpn_crypto
    )
    
    # 设置目标属性
    set_target_properties(test_crypto PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        OUTPUT_NAME "test_crypto"
    )
    
    # 包含目录
    target_include_directories(test_crypto 
        PRIVATE 
            ${CMAKE_SOURCE_DIR}/include
    )
    
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
    message(WARNING "sduvpn_crypto target not found, skipping crypto tests")
endif()

# =============================================================================
# 安装配置
# =============================================================================
if(TARGET test_crypto)
    install(TARGETS test_crypto
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
