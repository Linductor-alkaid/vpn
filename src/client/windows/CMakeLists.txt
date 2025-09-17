# Windows客户端CMakeLists.txt

# 设置最低CMake版本
cmake_minimum_required(VERSION 3.16)

# 只在Windows平台构建
if(NOT WIN32)
    message(FATAL_ERROR "Windows client can only be built on Windows platform")
endif()

# 设置项目名称
project(SDUVPNWindowsClient)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/json/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/spdlog/include)

# 源文件
set(WINDOWS_CLIENT_SOURCES
    main.cpp
    windows_tap_interface.cpp
    windows_vpn_client.cpp
    windows_service.cpp
    web_server.cpp
    config_manager.cpp
)

# 头文件
set(WINDOWS_CLIENT_HEADERS
    ${CMAKE_SOURCE_DIR}/include/client/windows_tap_interface.h
    ${CMAKE_SOURCE_DIR}/include/client/windows_vpn_client.h
    ${CMAKE_SOURCE_DIR}/include/client/windows_service.h
    ${CMAKE_SOURCE_DIR}/include/client/web_server.h
    ${CMAKE_SOURCE_DIR}/include/client/config_manager.h
)

# 创建可执行文件
add_executable(sduvpn-client ${WINDOWS_CLIENT_SOURCES} ${WINDOWS_CLIENT_HEADERS})

# 链接库
target_link_libraries(sduvpn-client
    sduvpn_crypto        # 加密库
    ws2_32              # Winsock库
    advapi32            # Windows API
    iphlpapi            # IP Helper API
    setupapi            # Setup API
    cfgmgr32            # Configuration Manager API
    netapi32            # Network API
    userenv             # User Environment API
    shell32             # Shell API
)

# 设置编译选项
if(MSVC)
    target_compile_options(sduvpn-client PRIVATE
        /W4                     # 警告级别4
        /WX-                    # 不将警告视为错误
        /permissive-           # 严格标准符合性
        /Zc:__cplusplus        # 正确的__cplusplus宏值
        /utf-8                 # UTF-8源文件编码
    )
    
    # 设置运行时库 - 使用动态运行时库与加密库保持一致
    target_compile_options(sduvpn-client PRIVATE
        $<$<CONFIG:Release>:/MD>
        $<$<CONFIG:Debug>:/MDd>
    )
        
    # 设置子系统
    set_target_properties(sduvpn-client PROPERTIES
        WIN32_EXECUTABLE FALSE  # 控制台应用程序
    )
else()
    target_compile_options(sduvpn-client PRIVATE
        -Wall -Wextra -Wpedantic
    )
endif()

# 设置输出目录
set_target_properties(sduvpn-client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin
)

# 定义预处理器宏
target_compile_definitions(sduvpn-client PRIVATE
    WIN32_LEAN_AND_MEAN     # 减少Windows头文件包含
    NOMINMAX                # 禁用min/max宏
    UNICODE                 # 使用Unicode
    _UNICODE                # 使用Unicode
    _WIN32_WINNT=0x0601     # Windows 7及以上
)

# 安装规则
install(TARGETS sduvpn-client
    RUNTIME DESTINATION bin
    COMPONENT client
)

# 安装配置文件示例
install(FILES
    ${CMAKE_SOURCE_DIR}/config/client.json.example
    DESTINATION config
    COMPONENT client
    RENAME client.json
)

# 创建安装包
if(WIN32)
    # 设置CPack变量
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_PACKAGE_NAME "SDUVPN Client")
    set(CPACK_PACKAGE_VENDOR "SDUVPN Project")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SDUVPN Windows Client")
    set(CPACK_PACKAGE_VERSION "1.0.0")
    set(CPACK_PACKAGE_VERSION_MAJOR "1")
    set(CPACK_PACKAGE_VERSION_MINOR "0")
    set(CPACK_PACKAGE_VERSION_PATCH "0")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "SDUVPN Client")
    
    # NSIS特定设置
    set(CPACK_NSIS_DISPLAY_NAME "SDUVPN Client")
    set(CPACK_NSIS_HELP_LINK "https://github.com/your-repo/sduvpn")
    set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/your-repo/sduvpn")
    set(CPACK_NSIS_CONTACT "your-email@example.com")
    set(CPACK_NSIS_MODIFY_PATH ON)
    
    # 安装TAP驱动
    set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "
        ExecWait '\\\"$INSTDIR\\\\third_party\\\\tap-windows-9.24.7-I601-Win10.exe\\\" /S'
    ")
    
    # 卸载时停止服务
    set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "
        ExecWait '\\\"$INSTDIR\\\\bin\\\\sduvpn-client.exe\\\" service stop'
        ExecWait '\\\"$INSTDIR\\\\bin\\\\sduvpn-client.exe\\\" service uninstall'
    ")
    
    include(CPack)
endif()

# 调试信息
message(STATUS "Windows Client configuration:")
message(STATUS "  Target: sduvpn-client")
message(STATUS "  Sources: ${WINDOWS_CLIENT_SOURCES}")
message(STATUS "  Output: ${CMAKE_BINARY_DIR}/bin/sduvpn-client.exe")
