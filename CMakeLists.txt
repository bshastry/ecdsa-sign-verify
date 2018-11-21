cmake_minimum_required (VERSION 2.6)
project(ECDSA_FUZZ)

include_directories("../openssl/include")
link_directories("../openssl")
add_executable(ecdsa_sign_verify sign-verify.c)
target_link_libraries(ecdsa_sign_verify crypto FuzzingEngine)
