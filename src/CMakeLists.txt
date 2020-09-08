cmake_minimum_required(VERSION 3.5.1)
project(lws-proto-parser)

#find_package(OpenSSL 1.0.2 REQUIRED)
#find_package(sodium 1.0.16 REQUIRED)


file(GLOB CAlgorithms_SRC "../external_libs/c-algorithms/src/*.c")
include_directories("../external_libs/c-algorithms/src/")

set(parser_src 
lws_proto_parser.h lws_proto_parser.c
uint256.h uint256.c
sharedkey.h sharedkey.cpp
${CAlgorithms_SRC}
)

add_library(lwsparser ${parser_src})
#target_link_libraries(lwsiot)

# client
set(parser_test_src parser_test.c)
add_executable(parser_test ${parser_test_src})
target_link_libraries(parser_test lwsiot lwsparser pthread sodium mbedtls mbedcrypto mbedx509 OpenSSL::Crypto )

# install
#set_target_properties(lwsiot PROPERTIES PUBLIC_HEADER "lwsiot.h")
#install(TARGETS lwsiot
 #       PUBLIC_HEADER DESTINATION include
  #      ARCHIVE DESTINATION lib)
