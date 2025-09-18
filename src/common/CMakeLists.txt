# SDUVPN 通用模块构建配置

# =============================================================================
# 通用库
# =============================================================================
set(COMMON_SOURCES
    secure_protocol.cpp
)

set(COMMON_HEADERS
    ${CMAKE_SOURCE_DIR}/include/common/secure_protocol.h
)

# 创建通用静态库
add_library(sduvpn_common STATIC ${COMMON_SOURCES} ${COMMON_HEADERS})

# 包含目录
target_include_directories(sduvpn_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# 链接依赖库
target_link_libraries(sduvpn_common
    sduvpn_crypto
)

# 平台特定设置
if(WIN32)
    target_link_libraries(sduvpn_common ws2_32)
    target_compile_definitions(sduvpn_common PRIVATE _WIN32_WINNT=0x0601)
endif()

# 编译选项
target_compile_features(sduvpn_common PRIVATE cxx_std_17)

# 设置属性
set_target_properties(sduvpn_common PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# 安装规则
install(TARGETS sduvpn_common
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
