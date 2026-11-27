add_executable(NativeDNS.Updater WIN32
  main.cpp
  zip_extract.cpp
  apply_update.cpp
  ../NativeDNS.GUI/windows_resources.rc
)
target_include_directories(NativeDNS.Updater PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../NativeDNS.GUI)
target_link_libraries(NativeDNS.Updater PRIVATE comctl32 shell32 user32 gdi32 advapi32)
set_target_properties(NativeDNS.Updater PROPERTIES
  OUTPUT_NAME Updater
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
install(TARGETS NativeDNS.Updater RUNTIME DESTINATION . COMPONENT Runtime)
