# Linux VPN Client
set(LINUX_CLIENT_SOURCES
    main.cpp
    linux_vpn_client.cpp
    linux_tun_interface.cpp
)

set(LINUX_CLIENT_HEADERS
    ${CMAKE_SOURCE_DIR}/include/client/linux_vpn_client.h
    ${CMAKE_SOURCE_DIR}/include/client/linux_tun_interface.h
)

# Linux客户端可执行文件
add_executable(sduvpn-client-linux ${LINUX_CLIENT_SOURCES} ${LINUX_CLIENT_HEADERS})

# 链接库
target_link_libraries(sduvpn-client-linux
    sduvpn-common
    sduvpn-crypto
    pthread
)

# 包含目录
target_include_directories(sduvpn-client-linux PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/asio
    ${CMAKE_SOURCE_DIR}/third_party/spdlog/include
    ${CMAKE_SOURCE_DIR}/third_party/json/include
)

# 编译选项
target_compile_features(sduvpn-client-linux PRIVATE cxx_std_17)

# 安装
install(TARGETS sduvpn-client-linux
    RUNTIME DESTINATION bin
)
