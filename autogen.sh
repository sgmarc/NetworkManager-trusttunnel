#!/bin/sh
# autogen.sh - Generate configure and build files
srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

which autoreconf >/dev/null || {
    echo "Error: autoreconf not found. Please install autoconf, automake and libtool."
    exit 1
}

autoreconf --force --install --verbose "$srcdir"
test -n "$NOCONFIGURE" || "$srcdir/configure" "$@"
