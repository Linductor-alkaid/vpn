# SDUVPN 第三方库配置
# 作者: SDUVPN Team
# 版本: 1.0

message(STATUS "配置第三方库...")

# 检查第三方库目录
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)
if(NOT EXISTS ${THIRD_PARTY_DIR})
    message(FATAL_ERROR "第三方库目录不存在: ${THIRD_PARTY_DIR}")
endif()

# =============================================================================
# JSON库配置 (nlohmann/json) - Header-only
# =============================================================================
set(JSON_DIR ${THIRD_PARTY_DIR}/json)
if(EXISTS ${JSON_DIR})
    set(JSON_INCLUDE_DIR ${JSON_DIR}/single_include)
    if(EXISTS ${JSON_INCLUDE_DIR})
        message(STATUS "✓ 找到 nlohmann/json: ${JSON_INCLUDE_DIR}")
        list(APPEND THIRD_PARTY_INCLUDE_DIRS ${JSON_INCLUDE_DIR})
    else()
        message(WARNING "✗ nlohmann/json 头文件目录不存在: ${JSON_INCLUDE_DIR}")
    endif()
else()
    message(WARNING "✗ nlohmann/json 未找到: ${JSON_DIR}")
endif()

# =============================================================================
# spdlog库配置 (Linux/Unix only - Windows uses iostream for logging)
# =============================================================================
if(NOT WIN32)
    set(SPDLOG_DIR ${THIRD_PARTY_DIR}/spdlog)
    if(EXISTS ${SPDLOG_DIR})
        message(STATUS "✓ 找到 spdlog: ${SPDLOG_DIR}")
        
        # spdlog配置选项
        set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
        set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)
        
        add_subdirectory(${SPDLOG_DIR} ${CMAKE_BINARY_DIR}/spdlog)
        list(APPEND THIRD_PARTY_LIBRARIES spdlog::spdlog)
    else()
        message(WARNING "✗ spdlog 未找到: ${SPDLOG_DIR}")
    endif()
else()
    message(STATUS "spdlog 在Windows平台上被禁用，使用标准iostream进行日志记录")
endif()

# =============================================================================
# GoogleTest配置 (仅用于测试，Linux/Unix only - Windows uses simple test framework)
# =============================================================================
if(NOT WIN32)
    set(GTEST_DIR ${THIRD_PARTY_DIR}/googletest)
    if(EXISTS ${GTEST_DIR})
        message(STATUS "✓ 找到 GoogleTest: ${GTEST_DIR}")
        
        # GoogleTest配置选项
        set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
        set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        
        add_subdirectory(${GTEST_DIR} ${CMAKE_BINARY_DIR}/googletest)
        list(APPEND TEST_LIBRARIES gtest gtest_main)
    else()
        message(WARNING "✗ GoogleTest 未找到: ${GTEST_DIR}")
    endif()
else()
    message(STATUS "GoogleTest 在Windows平台上被禁用，使用简单测试框架")
endif()

# =============================================================================
# Asio库配置 (Header-only, Standalone)
# =============================================================================
set(ASIO_DIR ${THIRD_PARTY_DIR}/asio)
if(EXISTS ${ASIO_DIR})
    set(ASIO_INCLUDE_DIR ${ASIO_DIR}/asio/include)
    if(EXISTS ${ASIO_INCLUDE_DIR})
        message(STATUS "✓ 找到 Asio: ${ASIO_INCLUDE_DIR}")
        list(APPEND THIRD_PARTY_INCLUDE_DIRS ${ASIO_INCLUDE_DIR})
        
        # Asio编译定义
        add_definitions(-DASIO_STANDALONE)
        add_definitions(-DASIO_NO_DEPRECATED)
        
        # Windows平台需要的额外库
        if(WIN32)
            list(APPEND THIRD_PARTY_LIBRARIES ws2_32 wsock32)
        endif()
    else()
        message(WARNING "✗ Asio 头文件目录不存在: ${ASIO_INCLUDE_DIR}")
    endif()
else()
    message(WARNING "✗ Asio 未找到: ${ASIO_DIR}")
endif()

# =============================================================================
# 平台特定配置
# =============================================================================
if(WIN32)
    # Windows平台额外库
    list(APPEND THIRD_PARTY_LIBRARIES 
        iphlpapi    # IP Helper API
        winmm       # Windows Multimedia API
    )
    
    # Windows版本定义
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
    add_definitions(-DWINVER=0x0601)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    
elseif(UNIX AND NOT ANDROID)
    # Linux平台
    list(APPEND THIRD_PARTY_LIBRARIES 
        pthread     # POSIX线程
        dl          # 动态链接库
    )
    
elseif(ANDROID)
    # Android平台
    list(APPEND THIRD_PARTY_LIBRARIES 
        log         # Android日志库
    )
endif()

# =============================================================================
# 导出变量到父作用域
# =============================================================================
set(THIRD_PARTY_INCLUDE_DIRS ${THIRD_PARTY_INCLUDE_DIRS} PARENT_SCOPE)
set(THIRD_PARTY_LIBRARIES ${THIRD_PARTY_LIBRARIES} PARENT_SCOPE)
set(TEST_LIBRARIES ${TEST_LIBRARIES} PARENT_SCOPE)

# 输出配置摘要
message(STATUS "========================================")
message(STATUS "第三方库配置完成")
message(STATUS "包含目录: ${THIRD_PARTY_INCLUDE_DIRS}")
message(STATUS "链接库: ${THIRD_PARTY_LIBRARIES}")
if(TEST_LIBRARIES)
    message(STATUS "测试库: ${TEST_LIBRARIES}")
endif()
message(STATUS "========================================")
