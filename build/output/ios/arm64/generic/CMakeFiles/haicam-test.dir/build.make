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
CMAKE_BINARY_DIR = /home/haicam/workspace/build/output/ios/arm64/generic

# Include any dependencies generated for this target.
include CMakeFiles/haicam-test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/haicam-test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/haicam-test.dir/flags.make

CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o: ../../../../../test/ContextTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o -c /home/haicam/workspace/test/ContextTest.cpp

CMakeFiles/haicam-test.dir/test/ContextTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/ContextTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/ContextTest.cpp > CMakeFiles/haicam-test.dir/test/ContextTest.cpp.i

CMakeFiles/haicam-test.dir/test/ContextTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/ContextTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/ContextTest.cpp -o CMakeFiles/haicam-test.dir/test/ContextTest.cpp.s

CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o: ../../../../../test/QRCodeScannerTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o -c /home/haicam/workspace/test/QRCodeScannerTest.cpp

CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/QRCodeScannerTest.cpp > CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.i

CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/QRCodeScannerTest.cpp -o CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.s

CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o: ../../../../../test/SoundWaveReceiverTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o -c /home/haicam/workspace/test/SoundWaveReceiverTest.cpp

CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/SoundWaveReceiverTest.cpp > CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.i

CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/SoundWaveReceiverTest.cpp -o CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.s

CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o: ../../../../../test/TCPTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o -c /home/haicam/workspace/test/TCPTest.cpp

CMakeFiles/haicam-test.dir/test/TCPTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/TCPTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/TCPTest.cpp > CMakeFiles/haicam-test.dir/test/TCPTest.cpp.i

CMakeFiles/haicam-test.dir/test/TCPTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/TCPTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/TCPTest.cpp -o CMakeFiles/haicam-test.dir/test/TCPTest.cpp.s

CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o: ../../../../../test/TimerTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o -c /home/haicam/workspace/test/TimerTest.cpp

CMakeFiles/haicam-test.dir/test/TimerTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/TimerTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/TimerTest.cpp > CMakeFiles/haicam-test.dir/test/TimerTest.cpp.i

CMakeFiles/haicam-test.dir/test/TimerTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/TimerTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/TimerTest.cpp -o CMakeFiles/haicam-test.dir/test/TimerTest.cpp.s

CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o: ../../../../../test/UDPTest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o -c /home/haicam/workspace/test/UDPTest.cpp

CMakeFiles/haicam-test.dir/test/UDPTest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/UDPTest.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/UDPTest.cpp > CMakeFiles/haicam-test.dir/test/UDPTest.cpp.i

CMakeFiles/haicam-test.dir/test/UDPTest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/UDPTest.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/UDPTest.cpp -o CMakeFiles/haicam-test.dir/test/UDPTest.cpp.s

CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o: CMakeFiles/haicam-test.dir/flags.make
CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o: ../../../../../test/UDPTest2.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o -c /home/haicam/workspace/test/UDPTest2.cpp

CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.i"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haicam/workspace/test/UDPTest2.cpp > CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.i

CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.s"
	/home/haicam/toolchain/iPhoneOS15.4/bin/arm-apple-darwin11-clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haicam/workspace/test/UDPTest2.cpp -o CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.s

# Object files for target haicam-test
haicam__test_OBJECTS = \
"CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o" \
"CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o"

# External object files for target haicam-test
haicam__test_EXTERNAL_OBJECTS =

haicam-test: CMakeFiles/haicam-test.dir/test/ContextTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/QRCodeScannerTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/SoundWaveReceiverTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/TCPTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/TimerTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/UDPTest.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/test/UDPTest2.cpp.o
haicam-test: CMakeFiles/haicam-test.dir/build.make
haicam-test: libhaicam-core_a.a
haicam-test: CMakeFiles/haicam-test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking CXX executable haicam-test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/haicam-test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/haicam-test.dir/build: haicam-test

.PHONY : CMakeFiles/haicam-test.dir/build

CMakeFiles/haicam-test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/haicam-test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/haicam-test.dir/clean

CMakeFiles/haicam-test.dir/depend:
	cd /home/haicam/workspace/build/output/ios/arm64/generic && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/haicam/workspace /home/haicam/workspace /home/haicam/workspace/build/output/ios/arm64/generic /home/haicam/workspace/build/output/ios/arm64/generic /home/haicam/workspace/build/output/ios/arm64/generic/CMakeFiles/haicam-test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/haicam-test.dir/depend

