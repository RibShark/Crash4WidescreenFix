cmake_minimum_required(VERSION 3.24)
project(Crash4WidescreenFix VERSION 1.0.0
                            DESCRIPTION "Enables >16:9 aspect ratios on Crash Bandicoot 4"
                            LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

add_library(Crash4WidescreenFix SHARED src/main.cpp src/stdafx.h src/HookInit.cpp
         external/ModUtils/Patterns.cpp  )
target_precompile_headers(Crash4WidescreenFix PRIVATE src/stdafx.h)

include_directories("external/ModUtils")

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 17 CXX_EXTENSIONS OFF CXX_STANDARD_REQUIRED ON SUFFIX ".asi")
