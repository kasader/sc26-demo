#!/usr/bin/env bash
ip netns del atk 2>/dev/null || true
ip netns del vic 2>/dev/null || true
echo "netns removed"
