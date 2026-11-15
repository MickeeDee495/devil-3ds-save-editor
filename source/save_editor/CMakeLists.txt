cmake_minimum_required(VERSION 3.14)
project(devil3ds_save_editor LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

add_subdirectory(mpqfs)

add_executable(devil3ds_save_editor main.cpp)

target_include_directories(devil3ds_save_editor PRIVATE
    mpqfs/include
)

target_link_libraries(devil3ds_save_editor PRIVATE
    mpqfs
    ctru
)

ctr_generate_smdh(devil3ds_save_editor.smdh
    NAME "Devil-3Ds Save Editor"
    DESCRIPTION "Adds Gold, Potions and Spells"
    AUTHOR "MickeeDee495"
)

ctr_create_3dsx(devil3ds_save_editor
    SMDH devil3ds_save_editor.smdh
)
