set(NATIVEDNS_CORE_COMMON_SOURCES
  src/core_api.cpp
  src/logger.cpp
  src/rules.cpp
  src/config.cpp
  src/dns_packet.cpp
  src/dns_secure.cpp
  src/dnscrypt.cpp
  src/router.cpp
  src/host.cpp
)

if(WIN32)
  set(NATIVEDNS_CORE_PLATFORM_SOURCES
    src/platform/windows/platform.cpp
    src/platform/windows/dns_transport.cpp
    src/platform/windows/local_proxy.cpp
    src/platform/windows/firewall.cpp
    src/platform/windows/tcp_dns_proxy.cpp
    src/platform/windows/windivert_interception.cpp
    src/platform/windows/interception_factory.cpp
    src/platform/windows/ipc.cpp
    src/platform/windows/autostart.cpp
  )
else()
  set(NATIVEDNS_CORE_PLATFORM_SOURCES
    src/platform/linux/platform.cpp
    src/platform/linux/dns_transport.cpp
    src/platform/linux/local_proxy.cpp
    src/platform/linux/linux_interception.cpp
    src/platform/linux/ipc.cpp
    src/platform/linux/autostart.cpp
  )
endif()

add_library(NativeDNS.Core.Objects OBJECT ${NATIVEDNS_CORE_COMMON_SOURCES} ${NATIVEDNS_CORE_PLATFORM_SOURCES})
target_include_directories(NativeDNS.Core.Objects PUBLIC include)
target_link_libraries(NativeDNS.Core.Objects PRIVATE CURL::libcurl Sodium::sodium)
if(WIN32)
  target_link_libraries(NativeDNS.Core.Objects PRIVATE WinDivert.Headers)
endif()
set_target_properties(NativeDNS.Core.Objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(NATIVEDNS_MODULAR)
  target_compile_definitions(NativeDNS.Core.Objects PRIVATE NATIVEDNS_EXPORTS)
  add_library(NativeDNS.Core SHARED $<TARGET_OBJECTS:NativeDNS.Core.Objects>)
  target_compile_definitions(NativeDNS.Core INTERFACE NATIVEDNS_IMPORTS)
  set_target_properties(NativeDNS.Core PROPERTIES OUTPUT_NAME NativeDNSCore)
else()
  add_library(NativeDNS.Core STATIC $<TARGET_OBJECTS:NativeDNS.Core.Objects>)
endif()

add_library(NativeDNS.Core.Internal STATIC $<TARGET_OBJECTS:NativeDNS.Core.Objects>)
foreach(target NativeDNS.Core NativeDNS.Core.Internal)
  target_include_directories(${target} PUBLIC include)
  target_link_libraries(${target} PUBLIC CURL::libcurl Sodium::sodium)
  if(WIN32)
    target_link_libraries(${target} PUBLIC ole32 oleaut32 taskschd advapi32 shell32 ws2_32 normaliz)
  else()
    target_link_libraries(${target} PUBLIC pthread)
  endif()
endforeach()

add_executable(NativeDNS.CoreHost host/main.cpp)
target_link_libraries(NativeDNS.CoreHost PRIVATE NativeDNS.Core.Internal)
set_target_properties(NativeDNS.CoreHost PROPERTIES OUTPUT_NAME NativeDNSCoreHost)
if(WIN32)
  set_target_properties(NativeDNS.CoreHost PROPERTIES WIN32_EXECUTABLE TRUE)
  if(MSVC)
    target_link_options(NativeDNS.CoreHost PRIVATE /ENTRY:mainCRTStartup)
  endif()
  nativedns_copy_windivert_runtime(NativeDNS.CoreHost)
  nativedns_copy_sodium_runtime(NativeDNS.CoreHost)
endif()
