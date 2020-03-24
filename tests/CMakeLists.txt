include_directories(..)

add_executable(tests test_transfer.cpp)
target_link_libraries(tests utp)

add_test(NAME tests COMMAND $<TARGET_FILE:tests>)
