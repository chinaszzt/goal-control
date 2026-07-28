#!/bin/sh -p
unset ENV BASH_ENV CDPATH GLOBIGNORE PS4
set +x
set -eu
LC_ALL=C
export LC_ALL

/bin/test "$#" -le 1 || {
  /bin/echo "canary-node-resolver: expected zero or one Node path" >&2
  exit 1
}

node_executable=
node_origin=auto
if /bin/test "$#" -eq 1; then
  node_origin=explicit
  requested_node_executable=$1
  case "$requested_node_executable" in
    *[[:cntrl:]]*)
      /bin/echo "canary-node-resolver: Node path contains control characters" >&2
      exit 1
      ;;
  esac
  case "$requested_node_executable" in
    /*) ;;
    *)
      /bin/echo "canary-node-resolver: Node path must be absolute" >&2
      exit 1
      ;;
  esac
  node_executable=$(/bin/realpath "$requested_node_executable") || {
    /bin/echo "canary-node-resolver: cannot resolve Node path" >&2
    exit 1
  }
  /bin/test "$node_executable" = "$requested_node_executable" || {
    /bin/echo "canary-node-resolver: Node path must be canonical" >&2
    exit 1
  }
else
  for node_candidate in \
    /opt/homebrew/opt/node@22/bin/node \
    /usr/local/opt/node@22/bin/node \
    /opt/homebrew/bin/node \
    /usr/local/bin/node \
    /usr/bin/node
  do
    if /bin/test -x "$node_candidate"; then
      node_executable=$(/bin/realpath "$node_candidate")
      break
    fi
  done
fi

/bin/test -n "$node_executable" || {
  /bin/echo "canary-node-resolver: no trusted Node candidate" >&2
  exit 1
}

/bin/test -f "$node_executable" && /bin/test -x "$node_executable" || {
  /bin/echo "canary-node-resolver: Node path is not an executable regular file" >&2
  exit 1
}
node_platform=$(/usr/bin/uname -s)
case "$node_platform" in
  Darwin)
    node_metadata=$(
      /usr/bin/stat -f '%HT|%l|%u|%Lp' "$node_executable"
    )
    ;;
  Linux)
    node_metadata=$(
      /usr/bin/stat -Lc '%F|%h|%u|%a' "$node_executable"
    )
    ;;
  *)
    /bin/echo "canary-node-resolver: unsupported host platform" >&2
    exit 1
    ;;
esac
node_type=${node_metadata%%|*}
node_metadata_tail=${node_metadata#*|}
node_nlink=${node_metadata_tail%%|*}
node_metadata_tail=${node_metadata_tail#*|}
node_uid=${node_metadata_tail%%|*}
node_mode=${node_metadata_tail#*|}
current_uid=$(/usr/bin/id -u)
case "$node_type" in
  "Regular File"|"regular file") ;;
  *)
    /bin/echo "canary-node-resolver: Node path is not an ordinary file" >&2
    exit 1
    ;;
esac
/bin/test "$node_nlink" = "1" || {
  /bin/echo "canary-node-resolver: Node path must be single-link" >&2
  exit 1
}
if /bin/test "$node_origin" = "auto"; then
  /bin/test "$node_uid" = "$current_uid" || /bin/test "$node_uid" = "0" || {
    /bin/echo "canary-node-resolver: auto-discovered Node path owner is not trusted" >&2
    exit 1
  }
fi
case "$node_mode" in
  [0-7][0-7][0-7]) ;;
  *)
    /bin/echo "canary-node-resolver: Node path mode is not ordinary" >&2
    exit 1
    ;;
esac
case "$node_mode" in
  *[2367][0-7]|*[0-7][2367])
    /bin/echo "canary-node-resolver: Node path is group/other writable" >&2
    exit 1
    ;;
esac

node_compatibility=$(
  /usr/bin/env -i \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/bin:/bin:/usr/sbin \
    TZ=UTC \
    "$node_executable" -e '
      const [major, minor] = process.versions.node.split(".").map(Number);
      if (
        !Number.isInteger(major)
        || !Number.isInteger(minor)
        || major < 22
        || (major === 22 && minor < 19)
      ) process.exit(86);
      process.stdout.write("CANARY_NODE_COMPATIBLE");
    '
) || {
  /bin/echo "canary-node-resolver: Node compatibility check failed" >&2
  exit 1
}
/bin/test "$node_compatibility" = "CANARY_NODE_COMPATIBLE" || {
  /bin/echo "canary-node-resolver: Node compatibility output mismatch" >&2
  exit 1
}

/usr/bin/printf '%s\n' "$node_executable"
