cmake_minimum_required(VERSION 3.16)
project(SDUVPN VERSION 1.0.0 LANGUAGES CXX)

# =============================================================================
# 项目基本配置
# =============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 构建类型
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "========================================")
message(STATUS "SDUVPN 配置信息")
message(STATUS "项目版本: ${PROJECT_VERSION}")
message(STATUS "构建类型: ${CMAKE_BUILD_TYPE}")
message(STATUS "编译器: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++标准: ${CMAKE_CXX_STANDARD}")

# =============================================================================
# 平台检测
# =============================================================================
if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
    message(STATUS "目标平台: Windows")
elseif(ANDROID)
    set(PLATFORM_ANDROID TRUE)
    message(STATUS "目标平台: Android")
elseif(UNIX)
    set(PLATFORM_LINUX TRUE)
    message(STATUS "目标平台: Linux")
else()
    message(FATAL_ERROR "不支持的平台")
endif()
message(STATUS "========================================")

# =============================================================================
# 编译选项
# =============================================================================
if(MSVC)
    # Visual Studio编译器选项
    add_compile_options(
        /W4                 # 警告级别4
        /permissive-        # 严格标准符合性
        /utf-8              # UTF-8编码
    )
    # 发布版本优化
    add_compile_options($<$<CONFIG:Release>:/O2>)
    add_compile_options($<$<CONFIG:Release>:/DNDEBUG>)
    
else()
    # GCC/Clang编译器选项
    add_compile_options(
        -Wall -Wextra       # 启用警告
        -pedantic           # 严格标准检查
    )
    # 发布版本优化
    add_compile_options($<$<CONFIG:Release>:-O3>)
    add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
    # 调试版本选项
    add_compile_options($<$<CONFIG:Debug>:-g>)
    add_compile_options($<$<CONFIG:Debug>:-O0>)
endif()

# =============================================================================
# 第三方库配置 (简化版本)
# =============================================================================
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)

# 初始化变量
set(THIRD_PARTY_INCLUDE_DIRS "")
set(THIRD_PARTY_LIBRARIES "")
set(TEST_LIBRARIES "")

# JSON库 (Header-only)
if(EXISTS ${THIRD_PARTY_DIR}/json/single_include)
    message(STATUS "✓ 找到 nlohmann/json")
    list(APPEND THIRD_PARTY_INCLUDE_DIRS ${THIRD_PARTY_DIR}/json/single_include)
else()
    message(WARNING "✗ nlohmann/json 未找到")
endif()

# spdlog库 (暂时禁用，避免编译问题)
# if(EXISTS ${THIRD_PARTY_DIR}/spdlog)
#     message(STATUS "✓ 找到 spdlog")
#     
#     # spdlog配置选项
#     set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
#     set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
#     set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
#     set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
#     set(SPDLOG_FMT_EXTERNAL OFF CACHE BOOL "" FORCE)
#     
#     add_subdirectory(${THIRD_PARTY_DIR}/spdlog)
#     list(APPEND THIRD_PARTY_LIBRARIES spdlog::spdlog)
# else()
#     message(WARNING "✗ spdlog 未找到")
# endif()

# Asio库 (Header-only)
if(EXISTS ${THIRD_PARTY_DIR}/asio/asio/include)
    message(STATUS "✓ 找到 Asio")
    list(APPEND THIRD_PARTY_INCLUDE_DIRS ${THIRD_PARTY_DIR}/asio/asio/include)
    
    # Asio编译定义
    add_definitions(-DASIO_STANDALONE)
    add_definitions(-DASIO_NO_DEPRECATED)
    
    # Windows平台需要的额外库
    if(WIN32)
        list(APPEND THIRD_PARTY_LIBRARIES ws2_32 wsock32)
    endif()
else()
    message(WARNING "✗ Asio 未找到")
endif()

# GoogleTest (暂时禁用，避免编译问题)
# if(EXISTS ${THIRD_PARTY_DIR}/googletest)
#     message(STATUS "✓ 找到 GoogleTest")
#     
#     set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
#     set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
#     set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
#     
#     add_subdirectory(${THIRD_PARTY_DIR}/googletest)
#     list(APPEND TEST_LIBRARIES gtest gtest_main)
# else()
#     message(WARNING "✗ GoogleTest 未找到")
# endif()

# Windows平台额外库
if(WIN32)
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
endif()

# =============================================================================
# 项目包含目录
# =============================================================================
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${THIRD_PARTY_INCLUDE_DIRS}
)

# =============================================================================
# 源代码目录
# =============================================================================
add_subdirectory(src)

# =============================================================================
# 测试配置
# =============================================================================
option(BUILD_TESTS "构建测试" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    message(STATUS "测试模块已启用")
else()
    message(STATUS "测试模块已禁用")
endif()

# =============================================================================
# 配置摘要
# =============================================================================
message(STATUS "")
message(STATUS "========================================")
message(STATUS "SDUVPN 配置完成")
message(STATUS "")
message(STATUS "包含目录: ${THIRD_PARTY_INCLUDE_DIRS}")
message(STATUS "链接库: ${THIRD_PARTY_LIBRARIES}")
if(TEST_LIBRARIES)
    message(STATUS "测试库: ${TEST_LIBRARIES}")
endif()
message(STATUS "========================================")
