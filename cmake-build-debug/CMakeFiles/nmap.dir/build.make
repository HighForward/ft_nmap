# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/c/Users/Forward/Desktop/nmap

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/nmap.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/nmap.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/nmap.dir/flags.make

CMakeFiles/nmap.dir/srcs/main.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/main.c.o: ../srcs/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/nmap.dir/srcs/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/main.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/main.c

CMakeFiles/nmap.dir/srcs/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/main.c > CMakeFiles/nmap.dir/srcs/main.c.i

CMakeFiles/nmap.dir/srcs/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/main.c -o CMakeFiles/nmap.dir/srcs/main.c.s

CMakeFiles/nmap.dir/srcs/main.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/main.c.o.requires

CMakeFiles/nmap.dir/srcs/main.c.o.provides: CMakeFiles/nmap.dir/srcs/main.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/main.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/main.c.o.provides

CMakeFiles/nmap.dir/srcs/main.c.o.provides.build: CMakeFiles/nmap.dir/srcs/main.c.o


CMakeFiles/nmap.dir/srcs/utils.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/utils.c.o: ../srcs/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/nmap.dir/srcs/utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/utils.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/utils.c

CMakeFiles/nmap.dir/srcs/utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/utils.c > CMakeFiles/nmap.dir/srcs/utils.c.i

CMakeFiles/nmap.dir/srcs/utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/utils.c -o CMakeFiles/nmap.dir/srcs/utils.c.s

CMakeFiles/nmap.dir/srcs/utils.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/utils.c.o.requires

CMakeFiles/nmap.dir/srcs/utils.c.o.provides: CMakeFiles/nmap.dir/srcs/utils.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/utils.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/utils.c.o.provides

CMakeFiles/nmap.dir/srcs/utils.c.o.provides.build: CMakeFiles/nmap.dir/srcs/utils.c.o


CMakeFiles/nmap.dir/srcs/icmp.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/icmp.c.o: ../srcs/icmp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/nmap.dir/srcs/icmp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/icmp.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/icmp.c

CMakeFiles/nmap.dir/srcs/icmp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/icmp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/icmp.c > CMakeFiles/nmap.dir/srcs/icmp.c.i

CMakeFiles/nmap.dir/srcs/icmp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/icmp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/icmp.c -o CMakeFiles/nmap.dir/srcs/icmp.c.s

CMakeFiles/nmap.dir/srcs/icmp.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/icmp.c.o.requires

CMakeFiles/nmap.dir/srcs/icmp.c.o.provides: CMakeFiles/nmap.dir/srcs/icmp.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/icmp.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/icmp.c.o.provides

CMakeFiles/nmap.dir/srcs/icmp.c.o.provides.build: CMakeFiles/nmap.dir/srcs/icmp.c.o


CMakeFiles/nmap.dir/srcs/args.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/args.c.o: ../srcs/args.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/nmap.dir/srcs/args.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/args.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/args.c

CMakeFiles/nmap.dir/srcs/args.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/args.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/args.c > CMakeFiles/nmap.dir/srcs/args.c.i

CMakeFiles/nmap.dir/srcs/args.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/args.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/args.c -o CMakeFiles/nmap.dir/srcs/args.c.s

CMakeFiles/nmap.dir/srcs/args.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/args.c.o.requires

CMakeFiles/nmap.dir/srcs/args.c.o.provides: CMakeFiles/nmap.dir/srcs/args.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/args.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/args.c.o.provides

CMakeFiles/nmap.dir/srcs/args.c.o.provides.build: CMakeFiles/nmap.dir/srcs/args.c.o


CMakeFiles/nmap.dir/srcs/host_resolve.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/host_resolve.c.o: ../srcs/host_resolve.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/nmap.dir/srcs/host_resolve.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/host_resolve.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/host_resolve.c

CMakeFiles/nmap.dir/srcs/host_resolve.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/host_resolve.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/host_resolve.c > CMakeFiles/nmap.dir/srcs/host_resolve.c.i

CMakeFiles/nmap.dir/srcs/host_resolve.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/host_resolve.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/host_resolve.c -o CMakeFiles/nmap.dir/srcs/host_resolve.c.s

CMakeFiles/nmap.dir/srcs/host_resolve.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/host_resolve.c.o.requires

CMakeFiles/nmap.dir/srcs/host_resolve.c.o.provides: CMakeFiles/nmap.dir/srcs/host_resolve.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/host_resolve.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/host_resolve.c.o.provides

CMakeFiles/nmap.dir/srcs/host_resolve.c.o.provides.build: CMakeFiles/nmap.dir/srcs/host_resolve.c.o


CMakeFiles/nmap.dir/srcs/tcp.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/tcp.c.o: ../srcs/tcp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/nmap.dir/srcs/tcp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/tcp.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/tcp.c

CMakeFiles/nmap.dir/srcs/tcp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/tcp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/tcp.c > CMakeFiles/nmap.dir/srcs/tcp.c.i

CMakeFiles/nmap.dir/srcs/tcp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/tcp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/tcp.c -o CMakeFiles/nmap.dir/srcs/tcp.c.s

CMakeFiles/nmap.dir/srcs/tcp.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/tcp.c.o.requires

CMakeFiles/nmap.dir/srcs/tcp.c.o.provides: CMakeFiles/nmap.dir/srcs/tcp.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/tcp.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/tcp.c.o.provides

CMakeFiles/nmap.dir/srcs/tcp.c.o.provides.build: CMakeFiles/nmap.dir/srcs/tcp.c.o


CMakeFiles/nmap.dir/srcs/fill_pkt.c.o: CMakeFiles/nmap.dir/flags.make
CMakeFiles/nmap.dir/srcs/fill_pkt.c.o: ../srcs/fill_pkt.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/nmap.dir/srcs/fill_pkt.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/nmap.dir/srcs/fill_pkt.c.o   -c /mnt/c/Users/Forward/Desktop/nmap/srcs/fill_pkt.c

CMakeFiles/nmap.dir/srcs/fill_pkt.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/nmap.dir/srcs/fill_pkt.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/Forward/Desktop/nmap/srcs/fill_pkt.c > CMakeFiles/nmap.dir/srcs/fill_pkt.c.i

CMakeFiles/nmap.dir/srcs/fill_pkt.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/nmap.dir/srcs/fill_pkt.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/Forward/Desktop/nmap/srcs/fill_pkt.c -o CMakeFiles/nmap.dir/srcs/fill_pkt.c.s

CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.requires:

.PHONY : CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.requires

CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.provides: CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.requires
	$(MAKE) -f CMakeFiles/nmap.dir/build.make CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.provides.build
.PHONY : CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.provides

CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.provides.build: CMakeFiles/nmap.dir/srcs/fill_pkt.c.o


# Object files for target nmap
nmap_OBJECTS = \
"CMakeFiles/nmap.dir/srcs/main.c.o" \
"CMakeFiles/nmap.dir/srcs/utils.c.o" \
"CMakeFiles/nmap.dir/srcs/icmp.c.o" \
"CMakeFiles/nmap.dir/srcs/args.c.o" \
"CMakeFiles/nmap.dir/srcs/host_resolve.c.o" \
"CMakeFiles/nmap.dir/srcs/tcp.c.o" \
"CMakeFiles/nmap.dir/srcs/fill_pkt.c.o"

# External object files for target nmap
nmap_EXTERNAL_OBJECTS =

nmap: CMakeFiles/nmap.dir/srcs/main.c.o
nmap: CMakeFiles/nmap.dir/srcs/utils.c.o
nmap: CMakeFiles/nmap.dir/srcs/icmp.c.o
nmap: CMakeFiles/nmap.dir/srcs/args.c.o
nmap: CMakeFiles/nmap.dir/srcs/host_resolve.c.o
nmap: CMakeFiles/nmap.dir/srcs/tcp.c.o
nmap: CMakeFiles/nmap.dir/srcs/fill_pkt.c.o
nmap: CMakeFiles/nmap.dir/build.make
nmap: CMakeFiles/nmap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking C executable nmap"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/nmap.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/nmap.dir/build: nmap

.PHONY : CMakeFiles/nmap.dir/build

CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/main.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/utils.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/icmp.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/args.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/host_resolve.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/tcp.c.o.requires
CMakeFiles/nmap.dir/requires: CMakeFiles/nmap.dir/srcs/fill_pkt.c.o.requires

.PHONY : CMakeFiles/nmap.dir/requires

CMakeFiles/nmap.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/nmap.dir/cmake_clean.cmake
.PHONY : CMakeFiles/nmap.dir/clean

CMakeFiles/nmap.dir/depend:
	cd /mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/Forward/Desktop/nmap /mnt/c/Users/Forward/Desktop/nmap /mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug /mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug /mnt/c/Users/Forward/Desktop/nmap/cmake-build-debug/CMakeFiles/nmap.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/nmap.dir/depend

