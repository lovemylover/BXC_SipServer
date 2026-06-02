cmake_minimum_required(VERSION 3.10.2)
project(BXC_SipServer)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread ")
set(CMAKE_BUILD_TYPE DEBUG)
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
message(STATUS "CMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}")

# 使用 Homebrew 安装的 libosip / libexosip
if(APPLE)
    # 自动检测 Homebrew 前缀
    execute_process(
        COMMAND brew --prefix
        OUTPUT_VARIABLE HOMEBREW_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(INCLUDE_DIR
        ${HOMEBREW_PREFIX}/include
        )
    set(LIB_DIR
        ${HOMEBREW_PREFIX}/lib
        )
else()
    set(INCLUDE_DIR
        /usr/include
        /usr/local/include
        )
    set(LIB_DIR
        /usr/lib
        /usr/local/lib
        )
endif()
include_directories(${INCLUDE_DIR})
link_directories(${LIB_DIR})

# macOS: 使用 @rpath 解决 dyld 动态库加载路径问题
if(APPLE)
    set(CMAKE_MACOSX_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH "${HOMEBREW_PREFIX}/lib")
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif()

add_executable(BXC_SipServer
        Utils/MD5.c
        Utils/HTTPDigest.c
        SipServer.cpp
        main.cpp
        )
TARGET_LINK_LIBRARIES(BXC_SipServer osip2 osipparser2 eXosip2)
