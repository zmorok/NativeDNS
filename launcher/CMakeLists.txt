add_executable(NativeDNS.Launcher WIN32 windows_main.cpp ../NativeDNS.GUI/windows_resources.rc)
target_include_directories(NativeDNS.Launcher PRIVATE ../NativeDNS.GUI)
target_link_libraries(NativeDNS.Launcher PRIVATE shell32 user32)
# The unified entry point loads packaged dynamic CRT/Qt/Core modules from bin/.
set_target_properties(NativeDNS.Launcher PROPERTIES
  OUTPUT_NAME NativeDNS
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
install(TARGETS NativeDNS.Launcher RUNTIME DESTINATION . COMPONENT Runtime)
