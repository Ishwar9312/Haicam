# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_SOURCE_DIR = /home/haicam/workspace

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/haicam/workspace/build/output/android/arm64-v8a/generic

# Include any dependencies generated for this target.
include CMakeFiles/haicam-core_a.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/haicam-core_a.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/haicam-core_a.dir/flags.make

CMakeFiles/haicam-core_a.dir/src/Context.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/Context.cpp.o: ../../../../../src/Context.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/haicam-core_a.dir/src/Context.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/Context.cpp.o -c /home/haicam/workspace/src/Context.cpp

CMakeFiles/haicam-core_a.dir/src/Context.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/Context.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/Context.cpp > CMakeFiles/haicam-core_a.dir/src/Context.cpp.i

CMakeFiles/haicam-core_a.dir/src/Context.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/Context.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/Context.cpp -o CMakeFiles/haicam-core_a.dir/src/Context.cpp.s

CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o: ../../../../../src/QRCodeScanner.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o -c /home/haicam/workspace/src/QRCodeScanner.cpp

CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/QRCodeScanner.cpp > CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.i

CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/QRCodeScanner.cpp -o CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.s

CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o: ../../../../../src/SoundWaveReceiver.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o -c /home/haicam/workspace/src/SoundWaveReceiver.cpp

CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/SoundWaveReceiver.cpp > CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.i

CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/SoundWaveReceiver.cpp -o CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.s

CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o: ../../../../../src/TCPClient.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o -c /home/haicam/workspace/src/TCPClient.cpp

CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/TCPClient.cpp > CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.i

CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/TCPClient.cpp -o CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.s

CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o: ../../../../../src/TCPConnection.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o -c /home/haicam/workspace/src/TCPConnection.cpp

CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/TCPConnection.cpp > CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.i

CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/TCPConnection.cpp -o CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.s

CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o: CMakeFiles/haicam-core_a.dir/flags.make
CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o: ../../../../../src/TCPServer.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o -c /home/haicam/workspace/src/TCPServer.cpp

CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.i"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/src/TCPServer.cpp > CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.i

CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.s"
	/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++ --target=aarch64-none-linux-android21 --sysroot=/home/haicam/toolchain/android-ndk-r24/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/src/TCPServer.cpp -o CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.s

# Object files for target haicam-core_a
haicam__core_a_OBJECTS = \
"CMakeFiles/haicam-core_a.dir/src/Context.cpp.o" \
"CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o" \
"CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o" \
"CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o" \
"CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o" \
"CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o"

# External object files for target haicam-core_a
haicam__core_a_EXTERNAL_OBJECTS =

libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/Context.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/QRCodeScanner.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/SoundWaveReceiver.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/TCPClient.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/TCPConnection.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/src/TCPServer.cpp.o
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/build.make
libhaicam-core_a.a: CMakeFiles/haicam-core_a.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking CXX static library libhaicam-core_a.a"
	$(CMAKE_COMMAND) -P CMakeFiles/haicam-core_a.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/haicam-core_a.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/haicam-core_a.dir/build: libhaicam-core_a.a

.PHONY : CMakeFiles/haicam-core_a.dir/build

CMakeFiles/haicam-core_a.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/haicam-core_a.dir/cmake_clean.cmake
.PHONY : CMakeFiles/haicam-core_a.dir/clean

CMakeFiles/haicam-core_a.dir/depend:
	cd /home/haicam/workspace/build/output/android/arm64-v8a/generic && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/haicam/workspace /home/haicam/workspace /home/haicam/workspace/build/output/android/arm64-v8a/generic /home/haicam/workspace/build/output/android/arm64-v8a/generic /home/haicam/workspace/build/output/android/arm64-v8a/generic/CMakeFiles/haicam-core_a.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/haicam-core_a.dir/depend

