find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Network)

add_library(NativeDNS.WindowActivation STATIC window_activation.cpp)
target_link_libraries(NativeDNS.WindowActivation PUBLIC Qt6::Widgets)
if(WIN32)
  target_sources(NativeDNS.WindowActivation PRIVATE window_activation_windows.cpp)
  target_link_libraries(NativeDNS.WindowActivation PRIVATE user32)
else()
  target_sources(NativeDNS.WindowActivation PRIVATE window_activation_linux.cpp)
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC ON)

set(NATIVEDNS_GUI_SOURCES
  qt_main.cpp
  qt_app.cpp
  update_checker.cpp
  log_filter_config.cpp
  log_filter.cpp
  log_filter_ui.cpp
  log_display.cpp
  action_icons.cpp
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
if(WIN32)
  set_target_properties(NativeDNS.GUI PROPERTIES OUTPUT_NAME NativeDNS.GUI)
else()
  set_target_properties(NativeDNS.GUI PROPERTIES OUTPUT_NAME NativeDNS)
endif()
target_link_libraries(NativeDNS.GUI PRIVATE NativeDNS.Core.Internal NativeDNS.WindowActivation Qt6::Widgets Qt6::Network)
target_compile_definitions(NativeDNS.GUI PRIVATE NATIVEDNS_VERSION="${PROJECT_VERSION}")
target_compile_definitions(NativeDNS.GUI PRIVATE NATIVEDNS_DIAGNOSTIC_DEFAULT=$<BOOL:${NATIVEDNS_DIAGNOSTIC_BUILD}>)

if(WIN32)
  target_link_libraries(NativeDNS.GUI PRIVATE shell32)
  nativedns_copy_windivert_runtime(NativeDNS.GUI)
  nativedns_copy_sodium_runtime(NativeDNS.GUI)
endif()
