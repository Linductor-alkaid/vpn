# SDUVPN 通用模块构建配置

# =============================================================================
# 通用库
# =============================================================================
set(COMMON_SOURCES
    secure_protocol.cpp
    web_server.cpp
    config_manager.cpp
)

set(COMMON_HEADERS
    ${CMAKE_SOURCE_DIR}/include/common/secure_protocol.h
    ${CMAKE_SOURCE_DIR}/include/common/web_server.h
    ${CMAKE_SOURCE_DIR}/include/common/config_manager.h
)

# 创建通用静态库
add_library(sduvpn-common STATIC ${COMMON_SOURCES} ${COMMON_HEADERS})

# 包含目录
target_include_directories(sduvpn-common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# 链接依赖库
target_link_libraries(sduvpn-common
    sduvpn-crypto
)

# 平台特定设置
if(WIN32)
    target_link_libraries(sduvpn-common ws2_32)
    target_compile_definitions(sduvpn-common PRIVATE _WIN32_WINNT=0x0601)
elseif(UNIX)
    target_link_libraries(sduvpn-common pthread)
endif()

# 编译选项
target_compile_features(sduvpn-common PRIVATE cxx_std_17)

# 设置属性
set_target_properties(sduvpn-common PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# 安装规则
install(TARGETS sduvpn-common
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
