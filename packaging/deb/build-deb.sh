#!/bin/sh
# Build a deb package for mcrelay using system-level paths.
#
# Default build: native architecture, binary -> /usr/bin/mcrelay
# For other architectures add --arch/--cc (cross-build toolchain required).

set -eu

PKG_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$PKG_DIR/../.." && pwd)

ARCH=$(dpkg --print-architecture)
CC=gcc
OUT_DIR="$PKG_DIR/out"

usage() {
	cat <<EOF
Usage: build-deb.sh [--arch ARCH] [--cc CC]

  --arch ARCH         Architecture field (default: $(dpkg --print-architecture))
  --cc CC             C compiler (default: gcc)
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--arch) ARCH="$2"; shift 2 ;;
		--cc) CC="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

# Version from src/define/global.h (MCRELAY_VERSION_DISPLAY, e.g. "1.2-beta7").
# Convert the first hyphen to a tilde so Debian version ordering puts
# pre-releases (1.2~beta7) below the final release (1.2).
DISPLAY=$(grep -E '^#define MCRELAY_VERSION_DISPLAY' "$ROOT/src/define/global.h" | sed -E 's/.*"([^"]+)".*/\1/')
UPSTREAM=$(printf '%s' "$DISPLAY" | sed 's/-/~/')
PKG_VERSION=${UPSTREAM}-1

BUILD_DIR="$ROOT/build-deb-$ARCH"
STAGING="$BUILD_DIR/staging"

echo "==> Building mcrelay $PKG_VERSION for $ARCH with $CC"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Configuring"
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$CC" -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF

echo "==> Compiling"
cmake --build "$BUILD_DIR" --parallel

echo "==> Assembling package root"
rm -rf "$STAGING"
mkdir -p "$STAGING"

install -D -m 0755 "$BUILD_DIR/mcrelay" "$STAGING/usr/bin/mcrelay"

# Use the cross-toolchain's strip when building for a foreign architecture;
# fall back to the native strip when --cc has no triple prefix (gcc).
STRIP=${CC%-gcc}-strip
command -v "$STRIP" >/dev/null 2>&1 || STRIP=strip
"$STRIP" --remove-section=.comment --strip-unneeded "$STAGING/usr/bin/mcrelay"

install -D -m 0644 "$ROOT/doc/configuration/mcrelay/config.json" "$STAGING/etc/mcrelay/config.json"
install -D -m 0644 "$PKG_DIR/mcrelay.logrotate" "$STAGING/etc/logrotate.d/mcrelay"
install -D -m 0644 "$PKG_DIR/systemd/mcrelay.service" "$STAGING/usr/lib/systemd/system/mcrelay.service"
install -D -m 0644 "$PKG_DIR/systemd/mcrelay@.service" "$STAGING/usr/lib/systemd/system/mcrelay@.service"
install -D -m 0644 "$PKG_DIR/mcrelay.bash-completion" "$STAGING/usr/share/bash-completion/completions/mcrelay"
install -D -m 0644 "$ROOT/README.md" "$STAGING/usr/share/doc/mcrelay/README.md"
install -D -m 0644 "$PKG_DIR/copyright" "$STAGING/usr/share/doc/mcrelay/copyright"
install -D -m 0644 "$ROOT/doc/information/loglevel.info" "$STAGING/usr/share/doc/mcrelay/loglevel.info"
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

CHANGELOG_TOP=$(head -1 "$PKG_DIR/changelog" | sed -E 's/^\S+\s+\(([^)]+)\).*/\1/')
if [ "$CHANGELOG_TOP" != "$PKG_VERSION" ]; then
	echo "FATAL: top changelog entry is '$CHANGELOG_TOP' but built version is '$PKG_VERSION'." >&2
	echo "       Edit packaging/deb/changelog and prepend a new entry for $PKG_VERSION." >&2
	exit 1
fi

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
