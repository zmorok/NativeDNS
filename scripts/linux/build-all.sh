#!/usr/bin/env bash
exec "$(dirname "$0")/build-linux.sh" "${1:-release}" all
