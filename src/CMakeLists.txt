# SDUVPN 源代码构建配置

# =============================================================================
# 已实现的模块
# =============================================================================
add_subdirectory(common)
add_subdirectory(crypto)

# 服务端模块 (仅在非Windows平台编译)
if(NOT WIN32)
    add_subdirectory(server)
    message(STATUS "Server module enabled for non-Windows platform")
else()
    message(STATUS "Server module disabled on Windows platform")
endif()

# =============================================================================
# 客户端模块
# =============================================================================
if(WIN32)
    add_subdirectory(client/windows)
elseif(UNIX AND NOT APPLE)
    add_subdirectory(client/linux)
endif()

# =============================================================================
# 未实现的模块 (暂时注释掉)
# =============================================================================
# add_subdirectory(client/android)    # 未实现
