# tests cmake:
cmake_minimum_required(VERSION 3.15...3.23)

project(CmakeConfigPackageTests
        VERSION ${PROJECT_VERSION}
        LANGUAGES CXX)

if (PROJECT_IS_TOP_LEVEL OR TEST_INSTALLED_VERSION)
    enable_testing()

    find_package(tcpp CONFIG REQUIRED)

    if (NOT TARGET tcpp_options)
        message(FATAL_ERROR "Required config package not found!")
        return()
    endif ()
endif ()

include(GoogleTest)

add_executable(tests
        ip_tests.cpp
        tcp_tests.cpp
        ../src/tcpp/net/conn.hpp
        ../src/tcpp/net/conn.cpp
        tcp_tests_sws.cpp)

set(SPDLOG_FMT_EXTERNAL ON)
target_link_libraries(tests PRIVATE fmt::fmt)

target_link_libraries(
        tests
        PRIVATE tcpp::tcpp_warnings
        tcpp::tcpp_options
        tcpp::netparser
        GTest::gtest_main
        GTest::gmock)

tcpp_configure_linker(tests)

if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
            TARGET tests
            PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:tests> $<TARGET_FILE_DIR:tests>
            COMMAND_EXPAND_LISTS)
endif ()

gtest_discover_tests(
        tests
        TEST_PREFIX
        "unittests."
        XML_OUTPUT_DIR
        .)
