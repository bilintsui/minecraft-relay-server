#!/bin/sh
# Build a deb package for mcrelay using system-level paths.
#
# Default build: native architecture, binary -> /usr/bin/mcrelay
# For other architectures add --arch/--cc (cross-build toolchain required).

set -eu

# Package contents must have predictable permissions regardless of the invoking shell.
umask 022

PKG_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$PKG_DIR/../.." && pwd)

ARCH=
CC=gcc
OUT_DIR="$PKG_DIR/out"

usage() {
	cat <<EOF
Usage: build-deb.sh [--arch ARCH] [--cc CC]

  --arch ARCH         Architecture field (default: native dpkg architecture)
  --cc CC             C compiler (default: gcc)
EOF
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'FATAL: required command not found: %s\n' "$1" >&2
		exit 1
	fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--arch|--cc)
			if [ $# -lt 2 ] || [ -z "$2" ]; then
				printf 'Missing value for %s\n' "$1" >&2; usage >&2; exit 2
			fi
			case "$2" in -*) printf 'Missing value for %s\n' "$1" >&2; usage >&2; exit 2 ;; esac
			if [ "$1" = --arch ]; then ARCH=$2; else CC=$2; fi
			shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

for tool in dpkg grep sed head; do require_command "$tool"; done
if [ -z "$ARCH" ]; then ARCH=$(dpkg --print-architecture); fi
case "$ARCH" in ''|-*|*[!a-z0-9-]*) printf 'FATAL: invalid package architecture: %s\n' "$ARCH" >&2; exit 2 ;; esac

# Version from src/define/global.h (MCRELAY_VERSION_DISPLAY, e.g. "1.2-beta7").
# Convert the first hyphen to a tilde so Debian version ordering puts
# pre-releases (1.2~beta7) below the final release (1.2).
DISPLAY=$(grep -E '^#define MCRELAY_VERSION_DISPLAY' "$ROOT/src/define/global.h" | sed -E 's/.*"([^"]+)".*/\1/')
UPSTREAM=$(printf '%s' "$DISPLAY" | sed 's/-/~/')
PKG_VERSION=${UPSTREAM}-1

if [ -z "$DISPLAY" ] || ! dpkg --validate-version "$PKG_VERSION"; then
	printf 'FATAL: invalid source package version: %s\n' "$PKG_VERSION" >&2
	exit 1
fi
CHANGELOG_TOP=$(head -1 "$PKG_DIR/changelog" | sed -n 's/^[^ ]*[[:space:]]*(\([^)]*\)).*/\1/p')
if [ "$CHANGELOG_TOP" != "$PKG_VERSION" ]; then
	printf "FATAL: top changelog entry is '%s' but built version is '%s'.\n" "$CHANGELOG_TOP" "$PKG_VERSION" >&2
	printf '       Prepend a matching entry to packaging/deb/changelog before building.\n' >&2
	exit 1
fi

for tool in cmake "$CC" pandoc dpkg-deb gzip install mktemp cat rm mkdir nproc du cut chmod find sort xargs md5sum; do require_command "$tool"; done
STRIP=$("$CC" -print-prog-name=strip 2>/dev/null) || STRIP=strip
if [ -z "$STRIP" ]; then STRIP=strip; fi
require_command "$STRIP"

# Compile/link only: a foreign-architecture probe must never be executed.
preflight_dir=$(mktemp -d "${TMPDIR:-/tmp}/mcrelay-deb-preflight.XXXXXX")
trap 'rm -rf "$preflight_dir"' 0
cat >"$preflight_dir/dependencies.c" <<'EOF'
#include <cjson/cJSON.h>
#include <resolv.h>
#include <stddef.h>
#include <systemd/sd-daemon.h>
int main(void) {
	cJSON_Delete(NULL);
	(void)sd_notify(0, "READY=1");
	return res_init();
}
EOF
if ! "$CC" -std=c99 -D_GNU_SOURCE "$preflight_dir/dependencies.c" -o "$preflight_dir/dependencies" -lcjson -lsystemd -lresolv >"$preflight_dir/compiler.log" 2>&1; then
	printf 'FATAL: compiler/development-library preflight failed for %s.\n' "$CC" >&2
	cat "$preflight_dir/compiler.log" >&2
	exit 1
fi
if ! "$STRIP" --remove-section=.comment --strip-unneeded "$preflight_dir/dependencies" >"$preflight_dir/strip.log" 2>&1; then
	printf 'FATAL: strip preflight failed for %s with compiler %s.\n' "$STRIP" "$CC" >&2
	cat "$preflight_dir/strip.log" >&2
	exit 1
fi
rm -rf "$preflight_dir"
trap - 0

BUILD_DIR="$ROOT/build-deb-$ARCH"
STAGING="$BUILD_DIR/staging"

echo "==> Building mcrelay $PKG_VERSION for $ARCH with $CC"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Configuring"
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$CC" -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF

echo "==> Compiling"
cmake --build "$BUILD_DIR" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-$(nproc)}"

echo "==> Assembling package root"
rm -rf "$STAGING"
mkdir -p "$STAGING"

install -D -m 0755 "$BUILD_DIR/mcrelay" "$STAGING/usr/bin/mcrelay"

"$STRIP" --remove-section=.comment --strip-unneeded "$STAGING/usr/bin/mcrelay"

install -D -m 0644 "$ROOT/doc/configuration/mcrelay/config.json" "$STAGING/etc/mcrelay/config.json"
install -D -m 0644 "$PKG_DIR/mcrelay.logrotate" "$STAGING/etc/logrotate.d/mcrelay"
install -D -m 0644 "$PKG_DIR/systemd/mcrelay.service" "$STAGING/usr/lib/systemd/system/mcrelay.service"
install -D -m 0644 "$PKG_DIR/systemd/mcrelay@.service" "$STAGING/usr/lib/systemd/system/mcrelay@.service"
install -D -m 0644 "$PKG_DIR/mcrelay.bash-completion" "$STAGING/usr/share/bash-completion/completions/mcrelay"
install -D -m 0644 "$ROOT/README.md" "$STAGING/usr/share/doc/mcrelay/README.md"
install -D -m 0644 "$PKG_DIR/copyright" "$STAGING/usr/share/doc/mcrelay/copyright"
install -D -m 0644 "$ROOT/doc/information/loglevel.info" "$STAGING/usr/share/doc/mcrelay/loglevel.info"
install -D -m 0644 "$ROOT/doc/information/metrics.md" "$STAGING/usr/share/doc/mcrelay/metrics.md"
install -D -m 0644 "$ROOT/doc/information/metrics-report.md" "$STAGING/usr/share/doc/mcrelay/metrics-report.md"
install -D -m 0644 "$ROOT/tools/metrics-report.py" "$STAGING/usr/share/doc/mcrelay/examples/metrics-report.py"
install -D -m 0644 "$ROOT/doc/configuration/mcrelay/config.jsonc" "$STAGING/usr/share/doc/mcrelay/examples/config.jsonc"

mandir="$STAGING/usr/share/man/man1"
mkdir -p "$mandir"
# Map pandoc's \f[CR] inline code font to bold (\f[B]) so groff does not warn
# about an unavailable "C"/"CR" font when rendering these man pages.
for src in mcrelay.1.md mcrelay-dumpconfig.1.md mcrelay-run.1.md mcrelay-version.1.md mcrelay-help.1.md; do
	out="$mandir/${src%.md}"
	pandoc -s -t man "$PKG_DIR/$src" -o "$out"
	sed -i 's/\\f\[CR\]/\\f[B]/g' "$out"
	gzip -9n -f "$out"
	chmod 0644 "$out.gz"
done

chmod 0755 "$STAGING/usr/share/man" "$mandir"

install -D -m 0644 "$PKG_DIR/changelog" "$STAGING/usr/share/doc/mcrelay/changelog.Debian"
gzip -9n -f "$STAGING/usr/share/doc/mcrelay/changelog.Debian"

INSTALLED_SIZE=$(du -sk "$STAGING" | cut -f1)

mkdir -p "$STAGING/DEBIAN"
sed "s/@VERSION@/$PKG_VERSION/; s/@ARCH@/$ARCH/; s/@INSTALLED_SIZE@/$INSTALLED_SIZE/" "$PKG_DIR/control.in" > "$STAGING/DEBIAN/control"
install -m 0644 "$PKG_DIR/conffiles" "$STAGING/DEBIAN/conffiles"
install -m 0755 "$PKG_DIR/postinst" "$STAGING/DEBIAN/postinst"
install -m 0755 "$PKG_DIR/postrm" "$STAGING/DEBIAN/postrm"
install -m 0755 "$PKG_DIR/prerm" "$STAGING/DEBIAN/prerm"

(
	cd "$STAGING"
	find . -type f ! -path './DEBIAN/*' -print0 | LC_ALL=C sort -z | xargs -0 md5sum | sed 's|  \./|  |'
) > "$STAGING/DEBIAN/md5sums"

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/mcrelay_${PKG_VERSION}_${ARCH}.deb"
rm -f "$DEB"

echo "==> Packaging"
dpkg-deb --build --root-owner-group "$STAGING" "$DEB"

echo
echo "==> Built: $DEB"
echo "==> Contents:"
dpkg-deb -I "$DEB"
dpkg-deb -c "$DEB"
