CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
project(hrtng)

#run ccmake to change IDASDK_VER
SET(IDASDK_VER "92" CACHE STRING "92" )
SET(IDASDK_DIR ${CMAKE_SOURCE_DIR}/../../idasdk${IDASDK_VER})
MESSAGE("${PROJECT_NAME}")
MESSAGE("Using IDA SDK dir: ${IDASDK_DIR}")
MESSAGE("-------------------")

IF (${IDASDK_VER} STRGREATER_EQUAL "85")
  SET(UNI64 1)
ELSE()
  SET(UNI64 0)
ENDIF ()

IF( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
ENDIF()
SET(CMAKE_SKIP_RPATH TRUE)

INCLUDE(ida_plugin.cmake)

ADD_IDA_PLUGIN(hrtng 
  hrtng.cpp
  apihashes.cpp
  appcall.cpp
  appcall_view.cpp
  cast.cpp
  callrefs.cpp
  comhelper.cpp
  config.cpp
  crpp.cpp
  ctreeg.cpp
  decr.cpp
  deinline.cpp
  deob.cpp
  regrefs.cpp
  helpers.cpp
  invert_if.cpp
  idb2pat.cpp
  lit.cpp
  MicrocodeExplorer.cpp
  microavx.cpp
  msig.cpp
  opt.cpp
  new_struc_place.cpp
  new_struc_view.cpp
  new_struct.cpp
  structures.cpp
  refactoring.cpp
  rename.cpp
  unflat.cpp
  varval.cpp
  )

if(NOT MSVC)
	add_compile_options(-flto)
endif()
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Build library tests")
add_subdirectory(cryptopp-cmake)
INCLUDE_DIRECTORIES(${cryptopp_INCLUDE_DIRS})

IF(NOT ${UNI64})
  TARGET_LINK_LIBRARIES(hrtng_64 cryptopp)
ENDIF()
TARGET_LINK_LIBRARIES(hrtng    cryptopp)
