#!/usr/bin/env bash

cd "$(dirname "$0")"

xcodebuild archive \
-scheme CppAbseil \
-destination "generic/platform=iOS" \
-archivePath ./Build/CppAbseil-iOS \
SKIP_INSTALL=NO \
BUILD_LIBRARY_FOR_DISTRIBUTION=YES

xcodebuild archive \
-scheme CppAbseil \
-destination "generic/platform=iOS Simulator" \
-archivePath ./Build/CppAbseil-Sim \
SKIP_INSTALL=NO \
BUILD_LIBRARY_FOR_DISTRIBUTION=YES

xcodebuild archive \
-scheme CppAbseil \
-destination "generic/platform=OS X" \
-archivePath ./Build/CppAbseil-OSX \
SKIP_INSTALL=NO \
BUILD_LIBRARY_FOR_DISTRIBUTION=YES

cd ./Build

xcodebuild -create-xcframework \
-framework ./CppAbseil-iOS.xcarchive/Products/Library/Frameworks/CppAbseil.framework \
-framework ./CppAbseil-Sim.xcarchive/Products/Library/Frameworks/CppAbseil.framework \
-framework ./CppAbseil-OSX.xcarchive/Products/Library/Frameworks/CppAbseil.framework \
-output ./CppAbseil.xcframework