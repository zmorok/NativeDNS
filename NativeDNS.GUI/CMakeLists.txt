find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Network)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC ON)

set(NATIVEDNS_GUI_SOURCES
  qt_main.cpp
  qt_app.cpp
  ui_preferences.cpp
  single_instance.cpp
  resources.qrc
)
if(WIN32)
  list(APPEND NATIVEDNS_GUI_SOURCES platform_launcher_windows.cpp windows_resources.rc)
else()
  list(APPEND NATIVEDNS_GUI_SOURCES platform_launcher_linux.cpp)
endif()

if(WIN32)
  add_executable(NativeDNS.GUI WIN32 ${NATIVEDNS_GUI_SOURCES})
else()
  add_executable(NativeDNS.GUI ${NATIVEDNS_GUI_SOURCES})
endif()
set_target_properties(NativeDNS.GUI PROPERTIES OUTPUT_NAME NativeDNS)
target_link_libraries(NativeDNS.GUI PRIVATE NativeDNS.Core.Internal Qt6::Widgets Qt6::Network)
target_compile_definitions(NativeDNS.GUI PRIVATE NATIVEDNS_VERSION="${PROJECT_VERSION}")

if(WIN32)
  target_link_libraries(NativeDNS.GUI PRIVATE shell32)
  nativedns_copy_windivert_runtime(NativeDNS.GUI)
  nativedns_copy_sodium_runtime(NativeDNS.GUI)
endif()
