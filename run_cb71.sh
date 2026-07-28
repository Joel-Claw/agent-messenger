#!/bin/bash
set -e
cd /home/alex/agent-messenger/server
echo "STEP1: Build check"
go build ./... 2>&1 || echo "BUILD FAILED"
echo "STEP2: Run CB71 tests"
go test -run "CB71" -count=1 -timeout 60s . 2>&1 || echo "TESTS FAILED"
echo "STEP3: Done"