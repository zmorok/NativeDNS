#!/usr/bin/env bash
exec "$(dirname "$0")/build-linux.sh" release "${1:-standalone}"
