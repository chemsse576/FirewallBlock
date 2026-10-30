cmake_minimum_required(VERSION 3.15)
project(FirewallBlock C)

set(CMAKE_C_STANDARD 11)

add_executable(FirewallBlock
    main.c
    firewall.c
    commun.c
)

target_link_libraries(FirewallBlock
    ole32
    oleaut32
    advapi32
    user32
)
