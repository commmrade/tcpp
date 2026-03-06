add_executable(main main.cpp)

target_link_libraries(
  main
  PRIVATE tcpp::tcpp_options
          tcpp::tcpp_warnings)

target_link_system_libraries(
  main
  PRIVATE
          fmt::fmt
          spdlog::spdlog
          lefticus::tools)


tcpp_configure_linker(main)

target_include_directories(main PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
