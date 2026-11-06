foreach(target NativeDNS.Launcher NativeDNS.DebugLauncher)
  add_executable(${target} WIN32 windows_main.cpp ../NativeDNS.GUI/windows_resources.rc)
  target_include_directories(${target} PRIVATE ../NativeDNS.GUI)
  target_link_libraries(${target} PRIVATE shell32 user32)
  # These entry points must run before the packaged dynamic CRT/Qt DLLs load.
  set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endforeach()
set_target_properties(NativeDNS.Launcher PROPERTIES OUTPUT_NAME NativeDNS)
set_target_properties(NativeDNS.DebugLauncher PROPERTIES OUTPUT_NAME NativeDNS.Debug)
target_compile_definitions(NativeDNS.DebugLauncher PRIVATE NATIVEDNS_DEBUG_LAUNCHER)
install(TARGETS NativeDNS.Launcher NativeDNS.DebugLauncher RUNTIME DESTINATION . COMPONENT Runtime)

# Console subsystem entry point preserves PowerShell wait, stdout and exit codes.
add_executable(NativeDNS.CliLauncher windows_main.cpp ../NativeDNS.GUI/windows_resources.rc)
target_include_directories(NativeDNS.CliLauncher PRIVATE ../NativeDNS.GUI)
target_link_libraries(NativeDNS.CliLauncher PRIVATE shell32 user32)
target_compile_definitions(NativeDNS.CliLauncher PRIVATE NATIVEDNS_CLI_LAUNCHER)
set_target_properties(NativeDNS.CliLauncher PROPERTIES OUTPUT_NAME nativednsctl
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
install(TARGETS NativeDNS.CliLauncher RUNTIME DESTINATION app/bin COMPONENT Tools)
