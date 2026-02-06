#!/bin/sh
# Common failure actions for initramfs scripts

fail_action() {
  action=${1:-panic}
  msg=${2:-"failure"}

  echo "FATAL: $msg" >&2

  case "$action" in
    panic)
      # Best-effort: try sysrq-trigger crash if available.
      if [ -w /proc/sysrq-trigger ]; then
        echo c > /proc/sysrq-trigger || true
      fi
      # Fall back to an endless loop.
      while true; do sleep 1; done
      ;;
    reboot)
      reboot -f || true
      while true; do sleep 1; done
      ;;
    shell)
      echo "Dropping to shell..." >&2
      sh -i
      exit 1
      ;;
    exit)
      exit 1
      ;;
    *)
      echo "Unknown FAIL_ACTION: $action" >&2
      exit 1
      ;;
  esac
}
