cmake_minimum_required(VERSION 3.29)
project(WPA_Cracker C)

set(CMAKE_C_STANDARD 11)

file(READ cmake-build-debug/input.hc22000 hfile)

add_executable(WPA_Cracker main.c)
