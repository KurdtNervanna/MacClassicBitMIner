# Build the classic Mac app with Retro68:
#   cmake -S c -B build-mac -DCMAKE_TOOLCHAIN_FILE=<Retro68-build>/toolchain/m68k-apple-macos/cmake/retro68.toolchain.cmake
cmake_minimum_required(VERSION 3.9)
project(MacClassicBitMiner C)
add_application(MacClassicBitMiner CREATOR "BMnr"
    app/macminer.c app/dnr.c minercore.c)
