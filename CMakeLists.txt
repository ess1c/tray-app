cmake_minimum_required(VERSION 3.20)
project(TrayApp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ── MIDL: generate RPC stubs from IDL ──────────────────────────────
find_program(MIDL_EXECUTABLE midl
    HINTS "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64"
          "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64"
          "C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64"
)

set(IDL_FILE   ${CMAKE_CURRENT_SOURCE_DIR}/rpc/trayapp.idl)
set(ACF_FILE   ${CMAKE_CURRENT_SOURCE_DIR}/rpc/trayapp.acf)
set(RPC_GEN    ${CMAKE_CURRENT_BINARY_DIR}/rpc_gen)
file(MAKE_DIRECTORY ${RPC_GEN})

add_custom_command(
    OUTPUT  ${RPC_GEN}/trayapp_h.h
            ${RPC_GEN}/trayapp_c.c
            ${RPC_GEN}/trayapp_s.c
    COMMAND ${MIDL_EXECUTABLE}
            /acf "${ACF_FILE}"
            /h   trayapp_h.h
            /cstub trayapp_c.c
            /sstub trayapp_s.c
            /out "${RPC_GEN}"
            "${IDL_FILE}"
    DEPENDS ${IDL_FILE} ${ACF_FILE}
    COMMENT "MIDL: generating RPC stubs"
)

add_custom_target(rpc_stubs DEPENDS
    ${RPC_GEN}/trayapp_h.h
    ${RPC_GEN}/trayapp_c.c
    ${RPC_GEN}/trayapp_s.c
)

# ── TrayApp (GUI application) ─────────────────────────────────────
add_executable(TrayApp WIN32
    src/main.cpp
    src/resource.h
    src/resource.rc
    ${RPC_GEN}/trayapp_c.c
)
target_include_directories(TrayApp PRIVATE ${RPC_GEN})
target_link_libraries(TrayApp PRIVATE comctl32 rpcrt4)
add_dependencies(TrayApp rpc_stubs)

# ── TrayService (Windows service) ─────────────────────────────────
add_executable(TrayService
    service/service_main.cpp
    ${RPC_GEN}/trayapp_s.c
)
target_include_directories(TrayService PRIVATE ${RPC_GEN})
target_link_libraries(TrayService PRIVATE rpcrt4 wtsapi32 userenv)
add_dependencies(TrayService rpc_stubs)
