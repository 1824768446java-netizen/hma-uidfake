#!/system/bin/sh
# Kernel matches cmdline itself; this only installs the default patterns.
MODDIR=${0%/*}
PARAM=/sys/module/hma_uidfake/parameters/hide_cmdlines
LOG="$MODDIR/state/pidhide.log"
mkdir -p "$MODDIR/state"

PAT='oh_my_keymint/daemon,hide-root-module/permissions_service.sh'

i=0
while [ "$i" -lt 120 ]; do
  [ -f "$PARAM" ] && break
  sleep 1
  i=$((i + 1))
done

if [ ! -f "$PARAM" ]; then
  echo "[pidhide] no hide_cmdlines param $(date '+%m-%d %H:%M:%S')" >>"$LOG"
  exit 0
fi

echo -n "$PAT" >"$PARAM"
echo "[pidhide] cmdlines=$PAT $(date '+%m-%d %H:%M:%S')" >>"$LOG"
