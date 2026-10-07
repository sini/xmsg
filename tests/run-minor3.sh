#!/bin/sh
# usage: run-minor3.sh <test-binary>
# Replaces /proc with a tmpfs in a private user+mount namespace and plants a regular file
# at /proc/777/exe, then runs the cell. Touches no real process.
exec unshare -Urm sh -c 'mount -t tmpfs t /proc && mkdir /proc/777 && echo x > /proc/777/exe && XMSG_DELTA_NS=1 exec "$0" --exact delta_minor_3_live_root_no_file_fallback --ignored --test-threads=1' "$1"
