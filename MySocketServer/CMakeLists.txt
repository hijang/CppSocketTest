cmake_minimum_required(VERSION 3.0)
project(hello)
set(CMAKE_CXX_COMPILER g++)

AUX_SOURCE_DIRECTORY(./src DIR_SRCS)
message("DIR_SRCS = ${DIR_SRCS}")
# set(SOURCES src/hello.cpp)
add_executable(${PROJECT_NAME} ${DIR_SRCS})
find_package(OpenSSL REQUIRED)

target_link_libraries(${PROJECT_NAME} ssl crypto)