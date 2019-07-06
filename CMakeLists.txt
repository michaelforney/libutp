cmake_minimum_required(VERSION 2.8)
project(utp C)

if(WIN32)
    set(${PROJECT_NAME}_ADD_SOURCES
        win32_inet_ntop.c
    )
else()
    add_definitions(-DPOSIX)
endif()

include_directories(.)

add_library(${PROJECT_NAME} STATIC
    utp.c
    utp_utils.c
    ${${PROJECT_NAME}_ADD_SOURCES}
)

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(FILES utp.h utypes.h DESTINATION include/libutp)
