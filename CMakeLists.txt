cmake_minimum_required(VERSION 2.8)
project(utp C)

include_directories(.)

add_library(${PROJECT_NAME} STATIC
    utp.c
    utp_utils.c
    ${${PROJECT_NAME}_ADD_SOURCES}
)

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(FILES utp.h DESTINATION include/libutp)
