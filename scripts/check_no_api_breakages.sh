#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the WebAuthn Swift open source project
##
## Copyright (c) 2024 the WebAuthn Swift project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu

function usage() {
    echo >&2 "Usage: $0 REPO-GITHUB-URL NEW-VERSION OLD-VERSIONS..."
    echo >&2
    echo >&2 "This script requires a Swift 5.6+ toolchain."
    echo >&2
    echo >&2 "Examples:"
    echo >&2
    echo >&2 "Check between main and tag 1.0.0 of swift-webauthn:"
    echo >&2 "  $0 https://github.com/swift-server/swift-webauthn main 1.0.0"
    echo >&2
    echo >&2 "Check between HEAD and commit 681eb6f using the provided toolchain:"
    echo >&2 "  xcrun --toolchain org.swift.5120190702a $0 ../some-local-repo HEAD 681eb6f"
}

if [[ $# -lt 3 ]]; then
    usage
    exit 1
fi

tmpdir=$(mktemp -d /tmp/.check-api_XXXXXX)
repo_url=$1
new_tag=$2
shift 2

repodir="$tmpdir/repo"
git clone "$repo_url" "$repodir"
git -C "$repodir" fetch -q origin '+refs/pull/*:refs/remotes/origin/pr/*'
cd "$repodir"
git checkout -q "$new_tag"

for old_tag in "$@"; do
    echo "Checking public API breakages from $old_tag to $new_tag"

    swift package diagnose-api-breaking-changes "$old_tag"
done

echo done
