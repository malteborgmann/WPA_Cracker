cmake_minimum_required(VERSION 3.29)
project(WPA_Cracker C)

set(CMAKE_C_STANDARD 11)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_executable(WPA_Cracker main.c)

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)