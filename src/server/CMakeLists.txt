# SDUVPN 服务器构建配置

# =============================================================================
# 服务器源文件
# =============================================================================
set(SERVER_SOURCES
    server_config.cpp
    client_session.cpp
    tun_interface.cpp
    packet_router.cpp
    vpn_server.cpp
    main.cpp
)

# =============================================================================
# 创建服务器可执行文件
# =============================================================================
add_executable(sduvpn-server ${SERVER_SOURCES})

# 设置目标属性
set_target_properties(sduvpn-server PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# 包含目录
target_include_directories(sduvpn-server 
    PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 链接库
target_link_libraries(sduvpn-server 
    PRIVATE 
        sduvpn-common
        sduvpn-crypto
        ${THIRD_PARTY_LIBRARIES}
)

# 平台特定配置
if(WIN32)
    # Windows平台特定配置
    target_compile_definitions(sduvpn-server 
        PRIVATE
            _WIN32_WINNT=0x0601
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )
    
    # Windows需要的额外库
    target_link_libraries(sduvpn-server 
        PRIVATE 
            ws2_32
            wsock32
            iphlpapi
    )
    
elseif(UNIX AND NOT ANDROID)
    # Linux平台特定配置
    target_link_libraries(sduvpn-server 
        PRIVATE 
            pthread
            dl
    )
    
    # 如果支持JSON库，启用JSON支持
    if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/json/single_include)
        target_compile_definitions(sduvpn-server 
            PRIVATE 
                SDUVPN_USE_JSON
        )
    endif()
endif()

# 编译定义
target_compile_definitions(sduvpn-server 
    PRIVATE
        SDUVPN_SERVER_VERSION="1.0.0"
)

# Debug版本的额外定义
target_compile_definitions(sduvpn-server 
    PRIVATE
        $<$<CONFIG:Debug>:SDUVPN_DEBUG>
        $<$<CONFIG:Debug>:DEBUG>
)

# =============================================================================
# 安装配置
# =============================================================================
install(TARGETS sduvpn-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# 安装配置文件示例
install(FILES 
    ${CMAKE_SOURCE_DIR}/config/server.json.example
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sduvpn
    OPTIONAL
)

# 安装systemd服务文件 (仅Linux)
if(UNIX AND NOT ANDROID AND NOT APPLE)
    install(FILES 
        ${CMAKE_SOURCE_DIR}/scripts/sduvpn-server.service
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
        OPTIONAL
    )
endif()

# =============================================================================
# 开发辅助目标
# =============================================================================

# 创建符号链接到构建目录 (仅Unix系统)
if(UNIX)
    add_custom_target(server-link
        COMMAND ${CMAKE_COMMAND} -E create_symlink 
                ${CMAKE_CURRENT_BINARY_DIR}/sduvpn-server 
                ${CMAKE_SOURCE_DIR}/sduvpn-server
        DEPENDS sduvpn-server
        COMMENT "创建服务器可执行文件的符号链接"
    )
endif()

# 打包目标
add_custom_target(server-package
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
    DEPENDS sduvpn-server
    COMMENT "打包服务器文件"
)

# =============================================================================
# 测试目标 (如果启用测试)
# =============================================================================
if(BUILD_TESTS)
    # 这里可以添加服务器相关的测试
    # add_subdirectory(tests)
endif()

# =============================================================================
# 文档生成 (可选)
# =============================================================================
find_program(DOXYGEN_EXECUTABLE doxygen)
if(DOXYGEN_EXECUTABLE)
    add_custom_target(server-docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/docs/Doxyfile.server
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "生成服务器API文档"
        VERBATIM
    )
endif()

# =============================================================================
# 清理目标
# =============================================================================
add_custom_target(server-clean
    COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_BINARY_DIR}/sduvpn-server*
    COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_SOURCE_DIR}/sduvpn-server
    COMMENT "清理服务器构建文件"
)
