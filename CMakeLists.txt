cmake_minimum_required (VERSION 2.6)
project(ECDSA_FUZZ)
set(LANGUAGE CXX)

include_directories("/src/openssl/include")
link_directories("/src/openssl")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
add_executable(ecdsa_sign_verify sign-verify.c)
target_link_libraries(ecdsa_sign_verify crypto FuzzingEngine c++)
install(TARGETS ecdsa_sign_verify DESTINATION ${CMAKE_INSTALL_PREFIX})
