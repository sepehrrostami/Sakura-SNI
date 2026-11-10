#!/bin/sh
#
# Gradle wrapper start-up script for POSIX shells (minimal version).
# You can regenerate the full upstream script at any time with: ./gradlew wrapper
#

# Resolve APP_HOME (the directory containing this script), following symlinks.
app_path=$0
while [ -h "$app_path" ]; do
    ls=$(ls -ld "$app_path")
    link=${ls#*' -> '}
    case $link in
        /*) app_path=$link ;;
        *) app_path=${app_path%"${app_path##*/}"}$link ;;
    esac
done
APP_HOME=$(cd "${app_path%"${app_path##*/}"}." >/dev/null && pwd -P) || exit 1

CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar

# Cygwin / MSYS / Git Bash: hand Windows-style paths to java.exe
case "$(uname)" in
    CYGWIN* | MINGW* | MSYS*)
        if command -v cygpath >/dev/null 2>&1; then
            CLASSPATH=$(cygpath --path --mixed "$CLASSPATH")
        fi
        ;;
esac

if [ -n "$JAVA_HOME" ]; then
    JAVACMD=$JAVA_HOME/bin/java
    if [ ! -x "$JAVACMD" ] && [ ! -x "$JAVACMD.exe" ]; then
        echo "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME" >&2
        exit 1
    fi
else
    JAVACMD=java
    if ! command -v java >/dev/null 2>&1; then
        echo "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH." >&2
        exit 1
    fi
fi

# JAVA_OPTS / GRADLE_OPTS are intentionally word-split.
# shellcheck disable=SC2086
exec "$JAVACMD" -Xmx64m -Xms64m $JAVA_OPTS $GRADLE_OPTS \
    "-Dorg.gradle.appname=${0##*/}" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain "$@"
