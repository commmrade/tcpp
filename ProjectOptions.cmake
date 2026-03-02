include(cmake/SystemLink.cmake)
include(cmake/LibFuzzer.cmake)
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)


include(CheckCXXSourceCompiles)


macro(tcpp_supports_sanitizers)
  # Emscripten doesn't support sanitizers
  if(EMSCRIPTEN)
    set(SUPPORTS_UBSAN OFF)
    set(SUPPORTS_ASAN OFF)
  elseif((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND NOT WIN32)

    message(STATUS "Sanity checking UndefinedBehaviorSanitizer, it should be supported on this platform")
    set(TEST_PROGRAM "int main() { return 0; }")

    # Check if UndefinedBehaviorSanitizer works at link time
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=undefined")
    check_cxx_source_compiles("${TEST_PROGRAM}" HAS_UBSAN_LINK_SUPPORT)

    if(HAS_UBSAN_LINK_SUPPORT)
      message(STATUS "UndefinedBehaviorSanitizer is supported at both compile and link time.")
      set(SUPPORTS_UBSAN ON)
    else()
      message(WARNING "UndefinedBehaviorSanitizer is NOT supported at link time.")
      set(SUPPORTS_UBSAN OFF)
    endif()
  else()
    set(SUPPORTS_UBSAN OFF)
  endif()

  if((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND WIN32)
    set(SUPPORTS_ASAN OFF)
  else()
    if (NOT WIN32)
      message(STATUS "Sanity checking AddressSanitizer, it should be supported on this platform")
      set(TEST_PROGRAM "int main() { return 0; }")

      # Check if AddressSanitizer works at link time
      set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
      set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address")
      check_cxx_source_compiles("${TEST_PROGRAM}" HAS_ASAN_LINK_SUPPORT)

      if(HAS_ASAN_LINK_SUPPORT)
        message(STATUS "AddressSanitizer is supported at both compile and link time.")
        set(SUPPORTS_ASAN ON)
      else()
        message(WARNING "AddressSanitizer is NOT supported at link time.")
        set(SUPPORTS_ASAN OFF)
      endif()
    else()
      set(SUPPORTS_ASAN ON)
    endif()
  endif()
endmacro()

macro(tcpp_setup_options)
  option(tcpp_ENABLE_HARDENING "Enable hardening" ON)
  option(tcpp_ENABLE_COVERAGE "Enable coverage reporting" OFF)
  cmake_dependent_option(
    tcpp_ENABLE_GLOBAL_HARDENING
    "Attempt to push hardening options to built dependencies"
    ON
    tcpp_ENABLE_HARDENING
    OFF)

  tcpp_supports_sanitizers()

  if(NOT PROJECT_IS_TOP_LEVEL OR tcpp_PACKAGING_MAINTAINER_MODE)
    option(tcpp_ENABLE_IPO "Enable IPO/LTO" OFF)
    option(tcpp_WARNINGS_AS_ERRORS "Treat Warnings As Errors" OFF)
    option(tcpp_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(tcpp_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(tcpp_ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)
    option(tcpp_ENABLE_CPPCHECK "Enable cpp-check analysis" OFF)
    option(tcpp_ENABLE_PCH "Enable precompiled headers" OFF)
    option(tcpp_ENABLE_CACHE "Enable ccache" OFF)
  else()
    option(tcpp_ENABLE_IPO "Enable IPO/LTO" ON)
    option(tcpp_WARNINGS_AS_ERRORS "Treat Warnings As Errors" ON)
    option(tcpp_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" ${SUPPORTS_ASAN})
    option(tcpp_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" ${SUPPORTS_UBSAN})
    option(tcpp_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(tcpp_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(tcpp_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(tcpp_ENABLE_CLANG_TIDY "Enable clang-tidy" ON)
    option(tcpp_ENABLE_CPPCHECK "Enable cpp-check analysis" ON)
    option(tcpp_ENABLE_PCH "Enable precompiled headers" OFF)
    option(tcpp_ENABLE_CACHE "Enable ccache" ON)
  endif()

  if(NOT PROJECT_IS_TOP_LEVEL)
    mark_as_advanced(
      tcpp_ENABLE_IPO
      tcpp_WARNINGS_AS_ERRORS
      tcpp_ENABLE_SANITIZER_ADDRESS
      tcpp_ENABLE_SANITIZER_LEAK
      tcpp_ENABLE_SANITIZER_UNDEFINED
      tcpp_ENABLE_SANITIZER_THREAD
      tcpp_ENABLE_SANITIZER_MEMORY
      tcpp_ENABLE_UNITY_BUILD
      tcpp_ENABLE_CLANG_TIDY
      tcpp_ENABLE_CPPCHECK
      tcpp_ENABLE_COVERAGE
      tcpp_ENABLE_PCH
      tcpp_ENABLE_CACHE)
  endif()

  tcpp_check_libfuzzer_support(LIBFUZZER_SUPPORTED)
  if(LIBFUZZER_SUPPORTED AND (tcpp_ENABLE_SANITIZER_ADDRESS OR tcpp_ENABLE_SANITIZER_THREAD OR tcpp_ENABLE_SANITIZER_UNDEFINED))
    set(DEFAULT_FUZZER ON)
  else()
    set(DEFAULT_FUZZER OFF)
  endif()

  option(tcpp_BUILD_FUZZ_TESTS "Enable fuzz testing executable" ${DEFAULT_FUZZER})

endmacro()

macro(tcpp_global_options)
  if(tcpp_ENABLE_IPO)
    include(cmake/InterproceduralOptimization.cmake)
    tcpp_enable_ipo()
  endif()

  tcpp_supports_sanitizers()

  if(tcpp_ENABLE_HARDENING AND tcpp_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN 
       OR tcpp_ENABLE_SANITIZER_UNDEFINED
       OR tcpp_ENABLE_SANITIZER_ADDRESS
       OR tcpp_ENABLE_SANITIZER_THREAD
       OR tcpp_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    message("${tcpp_ENABLE_HARDENING} ${ENABLE_UBSAN_MINIMAL_RUNTIME} ${tcpp_ENABLE_SANITIZER_UNDEFINED}")
    tcpp_enable_hardening(tcpp_options ON ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()
endmacro()

macro(tcpp_local_options)
  if(PROJECT_IS_TOP_LEVEL)
    include(cmake/StandardProjectSettings.cmake)
  endif()

  add_library(tcpp_warnings INTERFACE)
  add_library(tcpp_options INTERFACE)

  include(cmake/CompilerWarnings.cmake)
  tcpp_set_project_warnings(
    tcpp_warnings
    ${tcpp_WARNINGS_AS_ERRORS}
    ""
    ""
    ""
    "")

  include(cmake/Linker.cmake)
  # Must configure each target with linker options, we're avoiding setting it globally for now

  if(NOT EMSCRIPTEN)
    include(cmake/Sanitizers.cmake)
    tcpp_enable_sanitizers(
      tcpp_options
      ${tcpp_ENABLE_SANITIZER_ADDRESS}
      ${tcpp_ENABLE_SANITIZER_LEAK}
      ${tcpp_ENABLE_SANITIZER_UNDEFINED}
      ${tcpp_ENABLE_SANITIZER_THREAD}
      ${tcpp_ENABLE_SANITIZER_MEMORY})
  endif()

  set_target_properties(tcpp_options PROPERTIES UNITY_BUILD ${tcpp_ENABLE_UNITY_BUILD})

  if(tcpp_ENABLE_PCH)
    target_precompile_headers(
      tcpp_options
      INTERFACE
      <vector>
      <string>
      <utility>)
  endif()

  if(tcpp_ENABLE_CACHE)
    include(cmake/Cache.cmake)
    tcpp_enable_cache()
  endif()

  include(cmake/StaticAnalyzers.cmake)
  if(tcpp_ENABLE_CLANG_TIDY)
    tcpp_enable_clang_tidy(tcpp_options ${tcpp_WARNINGS_AS_ERRORS})
  endif()

  if(tcpp_ENABLE_CPPCHECK)
    tcpp_enable_cppcheck(${tcpp_WARNINGS_AS_ERRORS} "" # override cppcheck options
    )
  endif()

  if(tcpp_ENABLE_COVERAGE)
    include(cmake/Tests.cmake)
    tcpp_enable_coverage(tcpp_options)
  endif()

  if(tcpp_WARNINGS_AS_ERRORS)
    check_cxx_compiler_flag("-Wl,--fatal-warnings" LINKER_FATAL_WARNINGS)
    if(LINKER_FATAL_WARNINGS)
      # This is not working consistently, so disabling for now
      # target_link_options(tcpp_options INTERFACE -Wl,--fatal-warnings)
    endif()
  endif()

  if(tcpp_ENABLE_HARDENING AND NOT tcpp_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN 
       OR tcpp_ENABLE_SANITIZER_UNDEFINED
       OR tcpp_ENABLE_SANITIZER_ADDRESS
       OR tcpp_ENABLE_SANITIZER_THREAD
       OR tcpp_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    tcpp_enable_hardening(tcpp_options OFF ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()

endmacro()
