#!/usr/bin/env bash
exec "$(dirname "$0")/build-linux.sh" debug "${1:-standalone}"
