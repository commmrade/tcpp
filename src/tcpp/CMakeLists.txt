add_executable(main main.cpp
        tun.cpp
        tun.hpp
        util.hpp
        net/tcp.cpp
        net/tcp.hpp
        net/conn.cpp
        net/conn.hpp
        net/common.hpp
        clock.cpp
        clock.hpp
)

add_custom_target(setcap
        COMMAND sudo setcap cap_net_admin+ep $<TARGET_FILE:main>
        DEPENDS main
        COMMENT "Granting CAP_NET_ADMIN (requires sudo)"
)

target_link_libraries(
  main
  PRIVATE tcpp::tcpp_options tcpp::netparser
          tcpp::tcpp_warnings)

target_link_system_libraries(
  main
  PRIVATE
          fmt::fmt
          spdlog::spdlog
)

target_compile_options(main PRIVATE -fno-omit-frame-pointer -g)


tcpp_configure_linker(main)

target_include_directories(main PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
