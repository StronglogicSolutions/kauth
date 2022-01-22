cmake_minimum_required(VERSION 2.8.4)
project(auth)
find_package(OpenSSL COMPONENTS Crypto SSL REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -g")
include_directories(src third_party/jwt-cpp/include third_party/cpp-httplib)

set(SOURCE_FILES
  src/main.cpp
)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} bcrypt pthread)
