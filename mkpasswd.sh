#!/usr/bin/env bash
read -p 'Password: ' -s pass
echo ""
printf '%s' "$pass" | sha256sum | cut -d ' ' -f1
