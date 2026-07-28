#!/bin/bash
set -e
cd /home/alex/agent-messenger
git add server/coverage_boost71_test.go
git commit -m "CB71: coverage tests for routeChatMessage, routeMessage, marshalOutgoingMessage, checkRateLimit, tieredRateLimitMiddleware, profile handlers, queue persist, rate limit tiers, tracing, logger, typing indicators, deleteConversation, storeMessagesBatch, and many more low-coverage functions"
git push origin main 2>&1
echo "PUSH COMPLETE"