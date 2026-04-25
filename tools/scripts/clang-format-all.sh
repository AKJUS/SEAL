#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

BASE_DIR=$(dirname "$0")
SEAL_ROOT_DIR=$BASE_DIR/../..
find "$SEAL_ROOT_DIR/native" \( -name '*.h' -o -name '*.cpp' \) -print0 \
    | xargs -0 clang-format -i
