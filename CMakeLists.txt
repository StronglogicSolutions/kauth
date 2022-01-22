cmake_minimum_required(VERSION 2.8.4)
project(auth)
find_package(OpenSSL COMPONENTS Crypto SSL REQUIRED)
find_library(PQXX_LIB pqxx)
find_library(PQ_LIB pq)
set(PQXX_STATIC_LIB "/usr/local/lib/libpqxx.a")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -g")
set(KDB_STATIC_LIB ${CMAKE_SOURCE_DIR}/third_party/kdb/libkdb.a)
include_directories(src third_party/jwt-cpp/include third_party/cpp-httplib third_party/kdb/include)

set(SOURCE_FILES
  src/main.cpp
)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${PQXX_LIB} ${PQ_LIB} ${KDB_STATIC_LIB} ${PQXX_STATIC_LIB} bcrypt pthread)
