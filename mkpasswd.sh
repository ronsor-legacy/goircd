#!/usr/bin/env bash
read -p 'Password: ' -s pass
echo ""
printf pass | sha256sum | cut -d ' ' -f1
