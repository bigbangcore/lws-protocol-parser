cmake_minimum_required(VERSION 3.5.1)
project(lws-proto-parser)

set(CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DENABLE_IOT_DEBUG -DENABLE_IOT_INFO -DENABLE_IOT_WARN -DENABLE_IOT_ERROR")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_IOT_DEBUG -DENABLE_IOT_INFO -DENABLE_IOT_WARN -DENABLE_IOT_ERROR")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-builtin-macro-redefined -D'__FILE__=\"$(subst $(realpath ${CMAKE_SOURCE_DIR})/,,$(abspath $<))\"'")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-builtin-macro-redefined -D'__FILE__=\"$(subst $(realpath ${CMAKE_SOURCE_DIR})/,,$(abspath $<))\"'")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DLOG_USE_COLOR")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLOG_USE_COLOR")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

# x86_64
set(CMAKE_PREFIX_PATH /usr/local)
set(CMAKE_INSTALL_PREFIX /usr/local)

# ti i386
#set(CMAKE_PREFIX_PATH /home/ti/ti-sdk-am335x-evm-06.00.00.00/linux-devkit/sysroots/armv7ahf-vfp-neon-3.2-oe-linux-gnueabi/usr/local)
#set(CMAKE_INSTALL_PREFIX /home/ti/ti-sdk-am335x-evm-06.00.00.00/linux-devkit/sysroots/armv7ahf-vfp-neon-3.2-oe-linux-gnueabi/usr/local)

find_package(OpenSSL 1.0.2 REQUIRED)

file(GLOB CAlgorithms_SRC "third-party/c-algorithms/src/*.c")
include_directories("third-party/c-algorithms/src/")

