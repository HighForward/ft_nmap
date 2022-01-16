cmake_minimum_required(VERSION 3.10)
project(nmap C)

set(CMAKE_C_STANDARD 11)

add_executable(nmap
        srcs/main.c srcs/utils.c srcs/icmp.c srcs/args.c srcs/host_resolve.c srcs/tcp.c srcs/fill_pkt.c)