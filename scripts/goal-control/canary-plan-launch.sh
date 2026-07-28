#!/bin/sh -p
unset ENV BASH_ENV CDPATH GLOBIGNORE PS4
set +x
set -eu

launcher_path=$(/bin/realpath "$0")
script_directory=$(/usr/bin/dirname -- "$launcher_path")
node_resolver=$(/bin/realpath "$script_directory/canary-node-resolver.sh")
if /bin/test "${1-}" = "--node-executable"; then
  /bin/test "$#" -ge 2 || {
    /bin/echo "canary-plan-launch: --node-executable requires a path" >&2
    exit 1
  }
  requested_node_executable=$2
  shift 2
  node_executable=$(
    /bin/sh -p "$node_resolver" "$requested_node_executable"
  )
else
  node_executable=$(/bin/sh -p "$node_resolver")
fi
goalctl=$(/bin/realpath "$script_directory/../goalctl.js")
goalctl_command=canary-plan
case "${1-}" in
  canary-bootstrap-plan|canary-bootstrap-inspect|canary-bootstrap-prepare)
    goalctl_command=$1
    shift
    ;;
esac

exec /usr/bin/env -i \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 \
  GIT_OPTIONAL_LOCKS=0 \
  GIT_TERMINAL_PROMPT=0 \
  LANG=C \
  LC_ALL=C \
  PATH=/usr/bin:/bin:/usr/sbin \
  TZ=UTC \
  "$node_executable" "$goalctl" "$goalctl_command" "$@"
