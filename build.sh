#!/usr/bin/env bash
#
# Runs ./gradlew with Android Studio's bundled JDK (JBR 21), whatever JAVA_HOME
# is set to in your shell. Gradle 8.14 does not support JDK 25.
#
# Usage:
#   ./build.sh                       # build the debug APK and install it on the connected device
#   ./build.sh :app:assembleDebug    # build only
#   ./build.sh :app:testDebugUnitTest
#   ./build.sh clean :app:assembleRelease --stacktrace
#
# Override the JDK lookup with ANDROID_STUDIO_JDK=/path/to/jdk/home.

set -euo pipefail

REQUIRED_MAJOR=21
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "build.sh: $*" >&2; exit 1; }

# Prints the major version of the JDK at $1 (for example "21").
java_major() {
    "$1/bin/java" -XshowSettings:properties -version 2>&1 \
        | awk -F'= ' '/java.specification.version/ { print $2; exit }'
}

candidates() {
    # An explicit override comes first.
    [[ -n "${ANDROID_STUDIO_JDK:-}" ]] && echo "$ANDROID_STUDIO_JDK"

    case "$(uname -s)" in
        Darwin)
            # Standard installs, user installs, and JetBrains Toolbox installs (stable, beta, canary).
            for app in \
                "/Applications/Android Studio.app" \
                "$HOME/Applications/Android Studio.app" \
                /Applications/Android\ Studio*.app \
                "$HOME"/Applications/Android\ Studio*.app \
                "$HOME"/Library/Application\ Support/JetBrains/Toolbox/apps/*/*/Android\ Studio*.app \
                "$HOME"/Library/Application\ Support/JetBrains/Toolbox/apps/*/*/*/Android\ Studio*.app; do
                echo "$app/Contents/jbr/Contents/Home"
            done
            ;;
        Linux)
            for dir in \
                /opt/android-studio \
                /usr/local/android-studio \
                "$HOME/android-studio" \
                /snap/android-studio/current/android-studio \
                "$HOME"/.local/share/JetBrains/Toolbox/apps/*/*/android-studio* \
                "$HOME"/.local/share/JetBrains/Toolbox/apps/android-studio*; do
                echo "$dir/jbr"
            done
            ;;
        MINGW* | MSYS* | CYGWIN*)
            for dir in \
                "/c/Program Files/Android/Android Studio" \
                "$HOME/AppData/Local/Programs/Android Studio"; do
                echo "$dir/jbr"
            done
            ;;
    esac
}

find_jdk() {
    local home major
    while IFS= read -r home; do
        [[ -x "$home/bin/java" ]] || continue
        major="$(java_major "$home")"
        if [[ "$major" == "$REQUIRED_MAJOR" ]]; then
            echo "$home"
            return 0
        fi
        echo "build.sh: skipping $home (JDK $major, need $REQUIRED_MAJOR)" >&2
    done < <(candidates)
    return 1
}

JDK_HOME="$(find_jdk)" || die "could not find Android Studio's JDK $REQUIRED_MAJOR.
  Install Android Studio, or set ANDROID_STUDIO_JDK to a JDK $REQUIRED_MAJOR home directory."

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
echo "Using JDK: $JAVA_HOME"

cd "$PROJECT_DIR"

# Finds adb: the SDK from local.properties, then ANDROID_HOME, then PATH.
find_adb() {
    local sdk
    sdk="$(sed -n 's/^sdk\.dir=//p' local.properties 2>/dev/null | head -n1)"
    for candidate in "$sdk" "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}"; do
        [[ -n "$candidate" && -x "$candidate/platform-tools/adb" ]] && { echo "$candidate/platform-tools/adb"; return 0; }
    done
    command -v adb
}

if [[ $# -eq 0 ]]; then
    # Default: build the debug APK and install it on the connected device.
    ADB="$(find_adb)" || die "adb not found. Install Android SDK platform-tools or set ANDROID_HOME."
    devices="$("$ADB" devices | awk 'NR > 1 && $2 == "device" { print $1 }')"
    if [[ -z "$devices" ]]; then
        "$ADB" devices -l >&2
        die "no connected Android device (check the USB cable and that USB debugging is allowed).
  To build without installing, run: ./build.sh :app:assembleDebug"
    fi
    echo "Installing on: $(echo "$devices" | paste -sd ' ' -)"
    set -- :app:installDebug
fi
# -Dorg.gradle.java.home makes the Gradle daemon use the same JDK, even if
# a daemon was started earlier with another one.
exec ./gradlew -Dorg.gradle.java.home="$JAVA_HOME" "$@"
