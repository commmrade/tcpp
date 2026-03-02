macro(tcpp_configure_linker project_name)
  set(tcpp_USER_LINKER_OPTION
    "DEFAULT"
      CACHE STRING "Linker to be used")
    set(tcpp_USER_LINKER_OPTION_VALUES "DEFAULT" "SYSTEM" "LLD" "GOLD" "BFD" "MOLD" "SOLD" "APPLE_CLASSIC" "MSVC")
  set_property(CACHE tcpp_USER_LINKER_OPTION PROPERTY STRINGS ${tcpp_USER_LINKER_OPTION_VALUES})
  list(
    FIND
    tcpp_USER_LINKER_OPTION_VALUES
    ${tcpp_USER_LINKER_OPTION}
    tcpp_USER_LINKER_OPTION_INDEX)

  if(${tcpp_USER_LINKER_OPTION_INDEX} EQUAL -1)
    message(
      STATUS
        "Using custom linker: '${tcpp_USER_LINKER_OPTION}', explicitly supported entries are ${tcpp_USER_LINKER_OPTION_VALUES}")
  endif()

  set_target_properties(${project_name} PROPERTIES LINKER_TYPE "${tcpp_USER_LINKER_OPTION}")
endmacro()
