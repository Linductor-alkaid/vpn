@echo off
chcp 65001 >nul
echo 正在设置第三方依赖...

cd /d "%~dp0.."

echo 创建third_party目录...
if not exist third_party mkdir third_party
cd third_party

echo.
echo [1/4] 下载nlohmann/json...
if exist json (
    echo json目录已存在，跳过下载
) else (
    git clone https://github.com/nlohmann/json.git json
    if %ERRORLEVEL% EQU 0 (
        cd json
        git checkout v3.11.2
        cd ..
        echo ✓ nlohmann/json 下载完成
    ) else (
        echo ✗ nlohmann/json 下载失败
    )
)

echo.
echo [2/4] 下载spdlog...
if exist spdlog (
    echo spdlog目录已存在，跳过下载
) else (
    git clone https://github.com/gabime/spdlog.git spdlog
    if %ERRORLEVEL% EQU 0 (
        cd spdlog
        git checkout v1.12.0
        cd ..
        echo ✓ spdlog 下载完成
    ) else (
        echo ✗ spdlog 下载失败
    )
)

echo.
echo [3/4] 下载GoogleTest...
if exist googletest (
    echo googletest目录已存在，跳过下载
) else (
    git clone https://github.com/google/googletest.git googletest
    if %ERRORLEVEL% EQU 0 (
        cd googletest
        git checkout v1.14.0
        cd ..
        echo ✓ GoogleTest 下载完成
    ) else (
        echo ✗ GoogleTest 下载失败
    )
)

echo.
echo [4/5] 下载Asio...
if exist asio (
    echo asio目录已存在，跳过下载
) else (
    git clone https://github.com/chriskohlhoff/asio.git asio
    if %ERRORLEVEL% EQU 0 (
        cd asio
        git checkout asio-1-28-0
        cd ..
        echo ✓ Asio 下载完成
    ) else (
        echo ✗ Asio 下载失败
    )
)

echo.
echo [5/5] 下载libsodium...
if exist libsodium (
    echo libsodium目录已存在，跳过下载
) else (
    git clone https://github.com/jedisct1/libsodium.git libsodium
    if %ERRORLEVEL% EQU 0 (
        cd libsodium
        git checkout 1.0.19-RELEASE
        cd ..
        echo ✓ libsodium 下载完成
    ) else (
        echo ✗ libsodium 下载失败
    )
)

echo.
echo ========================================
echo 第三方库下载完成！
echo ========================================
echo.
echo 下载的库：
if exist json echo ✓ nlohmann/json (v3.11.2)
if exist spdlog echo ✓ spdlog (v1.12.0)  
if exist googletest echo ✓ GoogleTest (v1.14.0)
if exist asio echo ✓ Asio (v1.28.0)
if exist libsodium echo ✓ libsodium (v1.0.19)
echo.
echo 接下来可以运行 cmake 配置项目
pause
