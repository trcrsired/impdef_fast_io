cmake_minimum_required(VERSION 3.22)

project(impdeffastio)

set(CMAKE_CXX_STANDARD 23)

add_executable(impdef_fast_io main.cc)
target_precompile_headers(impdef_fast_io PRIVATE pch.hpp)
target_include_directories(impdef_fast_io PRIVATE ${FAST_IO_DIR}/include)
