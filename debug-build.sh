#!/bin/sh
rm -rf build-debug
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug -DDEBUG_MODE=ON -DBUILD_TESTING=ON && cmake --build build-debug
