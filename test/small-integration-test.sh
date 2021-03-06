#!/bin/bash

#
# Test ossfs-fuse file system operations with
#

set -o errexit

# Require root
REQUIRE_ROOT=require-root.sh
#source $REQUIRE_ROOT

source integration-test-common.sh

start_s3proxy

#
# enable_content_md5
#    Causes ossfs to validate file contents.  This isn't included in the common
#    options used by start_ossfs because tests may be performance tests
# singlepart_copy_limit
#    Appeared in upstream ossfs-fuse tests, possibly a limitation of S3Proxy
#    TODO: github archaeology to see why it was added.  
#
start_ossfs -o enable_content_md5 \
           -o singlepart_copy_limit=$((10 * 1024))

./integration-test-main.sh

echo "$0: tests complete."
