cmake_minimum_required(VERSION 3.15)
project(kqueue_test LANGUAGES C OBJC)

if (APPLE)
    add_executable(main main.c)
    target_link_libraries(main PRIVATE "-framework Foundation")
    target_compile_definitions(main PRIVATE WATCH_DIR="${CMAKE_CURRENT_SOURCE_DIR}/watch_dir")
    target_include_directories(main PRIVATE
        modules/xhl/include
        )
endif()