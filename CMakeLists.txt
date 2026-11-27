cmake_minimum_required(VERSION 3.25)

set(NATIVEDNS_VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/VERSION")

if(NOT EXISTS "${NATIVEDNS_VERSION_FILE}")
  message(FATAL_ERROR "NativeDNS VERSION file is missing: ${NATIVEDNS_VERSION_FILE}")
endif()

file(STRINGS "${NATIVEDNS_VERSION_FILE}" NATIVEDNS_VERSION LIMIT_COUNT 1)
string(STRIP "${NATIVEDNS_VERSION}" NATIVEDNS_VERSION)

if(NOT NATIVEDNS_VERSION MATCHES "^[0-9]+\.[0-9]+\.[0-9]+$")
  message(FATAL_ERROR "Invalid NativeDNS version in VERSION: '${NATIVEDNS_VERSION}'")
endif()

project(NativeDNS VERSION ${NATIVEDNS_VERSION} LANGUAGES C CXX)

message(STATUS "NativeDNS version: ${PROJECT_VERSION}")

if(CMAKE_SIZEOF_VOID_P AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "NativeDNS currently supports x64 builds only")
endif()

if(WIN32)
  enable_language(RC)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NATIVEDNS_MODULAR "Build Core as NativeDNSCore shared library" OFF)
option(NATIVEDNS_BUILD_GUI "Build the Qt Widgets GUI" ON)
option(NATIVEDNS_BUILD_TOOLS "Build developer CLI tools" ON)
option(NATIVEDNS_ANALYZE "Enable compiler static analysis where supported" OFF)
option(NATIVEDNS_LIVE_TESTS "Enable external DNS integration tests" OFF)
option(NATIVEDNS_FUZZING "Build Clang libFuzzer targets" OFF)
option(NATIVEDNS_STRESS_TESTS "Build and register local proxy stress/benchmark tests" OFF)
option(NATIVEDNS_DIAGNOSTIC_BUILD "Start GUI and CoreHost with diagnostic logging defaults" OFF)

if(MSVC)
  # Qt's official MSVC builds use the dynamic CRT. Keep every NativeDNS
  # target/dependency on the same runtime (/MDd in Debug, /MD in Release).
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/W4> $<$<COMPILE_LANGUAGE:C,CXX>:/WX> $<$<COMPILE_LANGUAGE:C,CXX>:/utf-8> $<$<COMPILE_LANGUAGE:C,CXX>:/permissive->)
  if(NATIVEDNS_ANALYZE)
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/analyze>)
  endif()
else()
  add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:-Wall> $<$<COMPILE_LANGUAGE:C,CXX>:-Wextra> $<$<COMPILE_LANGUAGE:C,CXX>:-Wpedantic>)
  if(NATIVEDNS_ANALYZE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:--analyze>)
  endif()
endif()

if(WIN32)
  add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
elseif(UNIX AND NOT APPLE)
  add_compile_definitions(_GNU_SOURCE)
else()
  message(FATAL_ERROR "NativeDNS currently targets Windows and Linux")
endif()

# Define BUILD_TESTING before third-party configuration. The curl integration
# temporarily disables its own tests and restores this value afterwards.
include(CTest)
add_subdirectory(third_party)
add_subdirectory(NativeDNS.Core)
if(NATIVEDNS_BUILD_GUI)
  add_subdirectory(NativeDNS.GUI)
endif()
set(NATIVEDNS_INCLUDE_CLI ${NATIVEDNS_BUILD_TOOLS})
# The Windows diagnostic collector uses the same bounded CLI commands as
# manual inspection; its internal worker is part of the GUI runtime package.
if(WIN32 AND NATIVEDNS_BUILD_GUI)
  set(NATIVEDNS_INCLUDE_CLI ON)
endif()
if(NATIVEDNS_INCLUDE_CLI)
  add_subdirectory(tools)
endif()
if(WIN32 AND NATIVEDNS_BUILD_GUI)
  add_subdirectory(launcher)
  add_subdirectory(diagnostics)
endif()
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

if(WIN32)
  set(NATIVEDNS_RUNTIME_DEST "bin")
  set(NATIVEDNS_TOOLS_DEST "bin")
else()
  set(NATIVEDNS_RUNTIME_DEST "bin")
  set(NATIVEDNS_TOOLS_DEST "bin")
endif()

if(WIN32)
  if(NATIVEDNS_BUILD_GUI)
    install(FILES "$<TARGET_FILE:NativeDNS.GUI>" DESTINATION bin COMPONENT Runtime)
  endif()
  install(FILES "$<TARGET_FILE:NativeDNS.CoreHost.Module>" DESTINATION bin COMPONENT Runtime)
  if(NATIVEDNS_INCLUDE_CLI AND NATIVEDNS_BUILD_GUI)
    install(FILES "$<TARGET_FILE:NativeDNS.Cli.Module>" DESTINATION bin COMPONENT Tools)
  elseif(NATIVEDNS_INCLUDE_CLI)
    install(TARGETS nativednsctl RUNTIME DESTINATION bin COMPONENT Tools)
  endif()
else()
  if(NATIVEDNS_BUILD_GUI)
    install(TARGETS NativeDNS.GUI RUNTIME DESTINATION ${NATIVEDNS_RUNTIME_DEST} COMPONENT Runtime)
  endif()
  install(TARGETS NativeDNS.CoreHost RUNTIME DESTINATION ${NATIVEDNS_RUNTIME_DEST} COMPONENT Runtime)
  if(NATIVEDNS_INCLUDE_CLI)
    install(TARGETS nativednsctl RUNTIME DESTINATION ${NATIVEDNS_TOOLS_DEST} COMPONENT Tools)
  endif()
endif()

if(WIN32)
  install(FILES
    "${NATIVEDNS_WINDIVERT_ROOT}/x64/WinDivert.dll"
    "${NATIVEDNS_WINDIVERT_ROOT}/x64/WinDivert64.sys"
    DESTINATION bin/drivers COMPONENT Runtime)
  install(FILES "${NATIVEDNS_WINDIVERT_ROOT}/LICENSE" DESTINATION docs/licenses RENAME WinDivert.txt COMPONENT Runtime)
  install(IMPORTED_RUNTIME_ARTIFACTS Sodium.Shared RUNTIME DESTINATION bin COMPONENT Runtime)
  install(FILES "${CMAKE_SOURCE_DIR}/packaging/windows/qt.conf" DESTINATION bin COMPONENT Runtime)
  install(DIRECTORY DESTINATION logs COMPONENT Runtime)
endif()

if(WIN32)
  file(READ "${CMAKE_SOURCE_DIR}/README.md" packaged_readme)
  string(REPLACE "(docs/" "(" packaged_readme "${packaged_readme}")
  file(WRITE "${CMAKE_BINARY_DIR}/packaged-README.md" "${packaged_readme}")
  install(FILES "${CMAKE_BINARY_DIR}/packaged-README.md" DESTINATION docs RENAME README.md COMPONENT Runtime)
  install(FILES "${CMAKE_SOURCE_DIR}/THIRD_PARTY_NOTICES.md" DESTINATION docs/licenses COMPONENT Runtime)
else()
  install(FILES "${CMAKE_SOURCE_DIR}/README.md" "${CMAKE_SOURCE_DIR}/THIRD_PARTY_NOTICES.md" DESTINATION . COMPONENT Runtime)
endif()
if(WIN32)
  install(FILES
    "${CMAKE_SOURCE_DIR}/third_party/licenses/curl.txt"
    "${CMAKE_SOURCE_DIR}/third_party/licenses/libsodium.txt"
    "${CMAKE_SOURCE_DIR}/third_party/licenses/nghttp2.txt"
    DESTINATION docs/licenses COMPONENT Runtime)
endif()
if(UNIX AND NOT APPLE AND NATIVEDNS_BUILD_GUI)
  install(FILES "${CMAKE_SOURCE_DIR}/packaging/linux/io.nativedns.NativeDNS.desktop" DESTINATION share/applications COMPONENT Runtime)
  # Keep the installed desktop/AppImage artwork identical to the Qt window and tray icon.
  install(FILES "${CMAKE_SOURCE_DIR}/NativeDNS.GUI/resources/nativedns.svg" DESTINATION share/icons/hicolor/scalable/apps COMPONENT Runtime)
endif()
install(FILES
  "${CMAKE_SOURCE_DIR}/docs/ARCHITECTURE.md"
  "${CMAKE_SOURCE_DIR}/docs/BUILD.md"
  "${CMAKE_SOURCE_DIR}/docs/CONFIG_FORMAT.md"
  "${CMAKE_SOURCE_DIR}/docs/DEPENDENCIES.md"
  "${CMAKE_SOURCE_DIR}/docs/DNS_TRANSPORTS.md"
  "${CMAKE_SOURCE_DIR}/docs/IPC_PROTOCOL.md"
  "${CMAKE_SOURCE_DIR}/docs/LINUX_INTERCEPTION.md"
  "${CMAKE_SOURCE_DIR}/docs/PLATFORM_MATRIX.md"
  DESTINATION docs COMPONENT Runtime)

if(WIN32)
  set(CPACK_GENERATOR ZIP)
  set(CPACK_PACKAGE_FILE_NAME "NativeDNS-${PROJECT_VERSION}-windows-x64-portable")
else()
  set(CPACK_GENERATOR "TGZ;DEB")
  set(CPACK_PACKAGE_FILE_NAME "NativeDNS-${PROJECT_VERSION}-linux-x64")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_PACKAGE_NAME nativedns)
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "NativeDNS")
  set(CPACK_DEBIAN_PACKAGE_SECTION net)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "nftables, policykit-1")
endif()
set(CPACK_PACKAGE_NAME NativeDNS)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
include(CPack)

if(WIN32)
  install(FILES "${CMAKE_SOURCE_DIR}/examples/log-filters.xml" DESTINATION docs/examples COMPONENT Runtime)
else()
  install(FILES "${CMAKE_SOURCE_DIR}/examples/log-filters.xml" DESTINATION examples COMPONENT Runtime)
endif()
