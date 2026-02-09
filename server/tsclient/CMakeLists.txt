# FreeRDP: tsclient macFUSE RDP server (skeleton)

# Avoid IPO/LTO in this target; some toolchains report unsupported IPO.
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION FALSE)

enable_language(CXX)

set(MODULE_NAME "tsclientd")

set(SRCS
    tsclientd.cpp
    rdp_server_core.cpp
    rdp_server_core.h
    rdpdr_backend.cpp
    rdpdr_backend.h
    rdpdr_transport.h
    vfs_frontend.cpp
    vfs_frontend.h
    winfsp_frontend.cpp
    winfsp_frontend.h
    path_mapper.cpp
    path_mapper.h
    ttl_cache.h
)

add_executable(${MODULE_NAME} ${SRCS})
set_target_properties(${MODULE_NAME} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

target_include_directories(${MODULE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND LIBS freerdp-server)
list(APPEND LIBS winpr freerdp)

target_link_libraries(${MODULE_NAME} ${LIBS})

option(WITH_MACFUSE "Enable macFUSE frontend" OFF)
if(WITH_MACFUSE)
  find_path(MACFUSE_INCLUDE_DIR fuse/fuse.h)
  if(NOT MACFUSE_INCLUDE_DIR)
    message(FATAL_ERROR "macFUSE headers not found. Install macFUSE or disable WITH_MACFUSE.")
  endif()
  find_library(MACFUSE_LIBRARY NAMES fuse osxfuse)
  if(NOT MACFUSE_LIBRARY)
    message(FATAL_ERROR "macFUSE library not found. Install macFUSE or disable WITH_MACFUSE.")
  endif()
  target_include_directories(${MODULE_NAME} PRIVATE ${MACFUSE_INCLUDE_DIR})
  target_compile_definitions(${MODULE_NAME} PRIVATE TSCLIENT_WITH_MACFUSE=1)
  target_compile_definitions(${MODULE_NAME} PRIVATE FUSE_USE_VERSION=29 _FILE_OFFSET_BITS=64)
  target_link_libraries(${MODULE_NAME} ${MACFUSE_LIBRARY})
endif()

option(WITH_WINFSP_SERVER "Enable WinFsp frontend (Windows)" OFF)
if(WITH_WINFSP_SERVER)
  if(WIN32)
    find_path(WINFSP_INCLUDE_DIR winfsp/winfsp.h)
    if(NOT WINFSP_INCLUDE_DIR)
      message(FATAL_ERROR "WinFsp headers not found. Install WinFsp or disable WITH_WINFSP_SERVER.")
    endif()
    find_library(WINFSP_LIBRARY NAMES winfsp-x64 winfsp)
    if(NOT WINFSP_LIBRARY)
      message(FATAL_ERROR "WinFsp library not found. Install WinFsp or disable WITH_WINFSP_SERVER.")
    endif()
    target_include_directories(${MODULE_NAME} PRIVATE ${WINFSP_INCLUDE_DIR})
    target_compile_definitions(${MODULE_NAME} PRIVATE TSCLIENT_WITH_WINFSP=1)
    target_link_libraries(${MODULE_NAME} ${WINFSP_LIBRARY})
  else()
    message(WARNING "WITH_WINFSP_SERVER is ON but this is not a Windows build. Ignoring.")
  endif()
endif()

install(TARGETS ${MODULE_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
set_property(TARGET ${MODULE_NAME} PROPERTY FOLDER "Server/Tsclient")

if(BUILD_TESTING)
  add_executable(tsclient-tests
      tsclient_tests.cpp
      rdpdr_backend.cpp
      path_mapper.cpp
  )
  target_include_directories(tsclient-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(tsclient-tests winpr freerdp)
  add_test(NAME tsclient-tests COMMAND tsclient-tests)
endif()
