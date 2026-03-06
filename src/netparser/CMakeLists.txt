include(GenerateExportHeader)


add_library(netparser netparser.cpp netparser.hpp)



add_library(tcpp::netparser ALIAS netparser)

target_link_libraries(netparser PRIVATE tcpp_options tcpp_warnings)

target_include_directories(netparser ${WARNING_GUARD} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)

if (tcpp_BUILD_FUZZ_TESTS)
    target_link_libraries(netparser PRIVATE -fsanitize=fuzzer-no-link)
    target_compile_options(netparser PRIVATE -fsanitize=fuzzer-no-link)
endif()

target_compile_features(netparser PUBLIC cxx_std_${CMAKE_CXX_STANDARD})

tcpp_configure_linker(netparser)

set_target_properties(
        netparser
        PROPERTIES VERSION ${PROJECT_VERSION}
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES)

generate_export_header(netparser EXPORT_FILE_NAME ${PROJECT_BINARY_DIR}/include/tcpp/netparser_export.hpp)

if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(netparser PUBLIC netparser_STATIC_DEFINE)
endif()