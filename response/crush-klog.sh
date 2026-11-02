#!/usr/bin/env bash
# crush-klog.sh - suspend, isolate, orphan and de-persist a suspected software keylogger.
#
# Default is DRY RUN. Nothing is suspended, moved or blocked without --apply.
# Every applied action is recorded, and RESTORE.sh undoes the whole run.
#
#   ./crush-klog.sh klog                 # report only
#   sudo ./crush-klog.sh klog --apply    # do it
#
# Design rules, in order of importance:
#   1. Volatile evidence is captured BEFORE anything is changed (order of volatility).
#   2. Children are suspended before parents, so a watchdog cannot respawn its child.
#   3. Nothing is deleted. Directories are renamed, files are moved, permissions are changed.
#   4. Anything that fails is reported as failed. No step is assumed to have worked.
#   5. The system clock is never touched: skewing it corrupts the timeline this tool exists to preserve.
set -uo pipefail

TARGET="${1:-}"
APPLY=0
OUT=""
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --out=*) OUT="${arg#*=}" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  esac
done

die() { printf 'REFUSED: %s\n' "$*" >&2; exit 2; }
[[ -n "$TARGET" ]] || die "usage: $0 <process-name-or-path> [--apply] [--out=DIR]"
[[ "$TARGET" == --* ]] && die "target must be a process name or path"

# Refuse to operate on a directory whose removal would break the system. Renaming /usr/bin is not
# containment, it is destruction.
REFUSE_PREFIXES=(/ /usr /usr/bin /usr/sbin /usr/lib /bin /sbin /lib /lib32 /lib64 /libx32 /etc
                  /boot /proc /sys /dev /var /run /root /home /tmp /opt /snap /nix)
is_refused_dir() {
  local d="${1%/}"
  [[ -z "$d" ]] && return 0
  for p in "${REFUSE_PREFIXES[@]}"; do [[ "$d" == "${p%/}" ]] && return 0; done
  return 1
}

SELF_PID=$$
SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")"
OUT="${OUT:-$HOME/klog-crush-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"/{evidence/artifacts,evidence/binary,persistence} || die "cannot create $OUT"
EVENTS="$OUT/events.jsonl"
: > "$EVENTS"
say() { printf '%s\n' "$*" | tee -a "$OUT/report.txt"; }
event() { printf '{"ts":"%s","phase":"%s","detail":"%s"}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$(printf '%s' "$2" | tr -d '"\\')" >> "$EVENTS"; }

say "crush-klog  run dir: $OUT"
say "mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo 'DRY RUN (nothing will be changed)')"
event start "$TARGET apply=$APPLY"
say "clock: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC, recorded and not altered)"

# ---------------------------------------------------------------- resolve
mapfile -t MATCH < <(pgrep -f -- "$TARGET" 2>/dev/null | grep -v -x -e "$SELF_PID" -e "$PPID" || true)
[[ ${#MATCH[@]} -eq 0 ]] && { say "no process matched '$TARGET'"; event nomatch "$TARGET"; exit 1; }

# Exclude anything that is this tool or its helpers: matching their own command line is a classic
# way to have the response tool suspend itself.
# A target can be hosted by an interpreter: /proc/pid/exe then points at python, bash or node, not at
# the implant. Resolving that wrong is not cosmetic - the tool would look for "bash" in persistence,
# copy /bin/bash as evidence and try to quarantine /usr/bin. So the interpreter is identified, the real
# target is taken from the command line, and the interpreter directory is never touched.
is_interpreter() {
  case "$(basename "$1")" in
    bash|sh|dash|zsh|ksh|python|python2|python3|python3.*|perl|ruby|node|nodejs|php|pwsh|powershell|java|mono) return 0 ;;
  esac
  return 1
}
first_real_arg() {
  local -a argv=(); local i a
  mapfile -d '' -t argv < "/proc/$1/cmdline" 2>/dev/null || return 1
  for ((i=1; i<${#argv[@]}; i++)); do
    a="${argv[$i]}"
    [[ -z "$a" || "$a" == -* ]] && continue
    [[ -f "$a" ]] && { readlink -f "$a"; return 0; }
  done
  return 1
}

EXES=(); ROOTS=(); HOSTED=()
for pid in "${MATCH[@]}"; do
  [[ ! -d "/proc/$pid" ]] && continue
  exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  [[ -z "$exe" ]] && continue
  # The tool's own command line contains the target string, so pgrep -f matches it. Excluding by
  # executable path alone missed that, and the tool tried to suspend itself.
  cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  [[ "$exe" == "$SELF_PATH" ]] && continue
  case "$cmdline" in *"/crush-klog.sh"*|*"crush-klog"*) continue ;; esac
  if is_interpreter "$exe"; then
    scripted="$(first_real_arg "$pid" || true)"
    if [[ -n "$scripted" && "$scripted" != "$exe" ]]; then
      ROOTS+=("$pid"); EXES+=("$scripted"); HOSTED+=("$exe")
      continue
    fi
    say "  skipping $pid: it is $exe itself, not a hosted target"
    continue
  fi
  ROOTS+=("$pid"); EXES+=("$exe"); HOSTED+=("")
done
[[ ${#ROOTS[@]} -eq 0 ]] && { say "matched processes were this tool itself; nothing to do"; exit 1; }

say ""
say "== matched =="
for i in "${!ROOTS[@]}"; do
  say "  pid ${ROOTS[$i]}  $(cat "/proc/${ROOTS[$i]}/comm" 2>/dev/null)  ${EXES[$i]}"
done

# ---------------------------------------------------------------- tree, children first
tree_children_first() {
  local pid="$1" child
  while read -r child; do
    [[ -z "$child" ]] && continue
    [[ "$child" == "$pid" ]] && continue
    tree_children_first "$child"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  printf '%s\n' "$pid"
}
TREE=()
for pid in "${ROOTS[@]}"; do
  while read -r p; do [[ -n "$p" ]] && TREE+=("$p"); done < <(tree_children_first "$pid")
done
# dedupe, preserve order: a child reachable from two roots must be suspended once
TREE=($(printf '%s\n' "${TREE[@]}" | awk '!seen[$0]++'))
for i in "${!HOSTED[@]}"; do
  [[ -n "${HOSTED[$i]}" ]] && say "  note: pid ${ROOTS[$i]} runs under ${HOSTED[$i]}, which is recorded but never modified"
done
say ""
say "== process tree (children first) =="
say "  ${TREE[*]}"

# ---------------------------------------------------------------- evidence, before mutation
say ""
say "== evidence =="
CAPTURED=0
for i in "${!ROOTS[@]}"; do
  pid="${ROOTS[$i]}"; exe="${EXES[$i]}"
  {
    printf 'pid %s\nppid %s\nuser %s\nexe %s\n' "$pid" \
      "$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null)" \
      "$(stat -c %U "/proc/$pid" 2>/dev/null)" "$exe"
    printf 'started %s\n' "$(stat -c %y "/proc/$pid" 2>/dev/null)"
    printf 'cmdline %s\n' "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
  } > "$OUT/evidence/pid-$pid.txt" 2>/dev/null
  if [[ -r "$exe" ]]; then
    sha256sum "$exe" >> "$OUT/evidence/hashes.txt" 2>/dev/null
    cp -a -- "$exe" "$OUT/evidence/binary/" 2>/dev/null && chmod 0400 "$OUT/evidence/binary/$(basename "$exe")"
    CAPTURED=$((CAPTURED+1))
  fi
done
# open sockets while they still exist: after suspension this map is intact, after restart it is gone
{ command -v ss >/dev/null && ss -tunp 2>/dev/null | grep -F -e "${EXES[0]}" ;
  command -v ss >/dev/null && ss -tunp 2>/dev/null | awk -v p="${ROOTS[0]}" '$0 ~ "pid="p","'; } \
  > "$OUT/evidence/sockets.txt" 2>/dev/null || true
say "  binaries copied and hashed: $CAPTURED"
say "  sockets recorded: $(wc -l < "$OUT/evidence/sockets.txt" 2>/dev/null || echo 0) line(s)"
event evidence "binaries=$CAPTURED"

# ---------------------------------------------------------------- persistence inventory
NAMES=(); PATHS=()
for exe in "${EXES[@]}"; do
  PATHS+=("$exe"); NAMES+=("$(basename "$exe")")
done
matches() {  # exact executable path, or the file name as a whole word: no loose substrings
  local hay="$1" n p
  for p in "${PATHS[@]}"; do [[ "$hay" == *"$p"* ]] && return 0; done
  for n in "${NAMES[@]}"; do
    [[ "$hay" == *"$n"* ]] || continue
    [[ "$hay" =~ (^|[[:space:]/"\'=])"$n"($|[[:space:]"\']) ]] && return 0
  done
  return 1
}

: > "$OUT/persistence/entries.tsv"
FOUND=0
add_entry() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$OUT/persistence/entries.tsv"; FOUND=$((FOUND+1)); }

# systemd units (system and user)
for d in /etc/systemd/system /lib/systemd/system "$HOME/.config/systemd/user"; do
  [[ -d "$d" ]] || continue
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    matches "$(grep -h -e '^ExecStart=' "$u" 2>/dev/null | head -1)" && add_entry systemd "$u" "$(basename "$u")"
  done < <(find "$d" -maxdepth 2 -name '*.service' 2>/dev/null)
done
# XDG autostart
for f in "$HOME"/.config/autostart/*.desktop; do
  [[ -f "$f" ]] || continue
  matches "$(grep -h '^Exec=' "$f" 2>/dev/null | head -1)" && add_entry autostart "$f" "$(basename "$f")"
done
# crontab: recorded verbatim before any change, restored from the copy
if command -v crontab >/dev/null 2>&1 && crontab -l >/dev/null 2>&1; then
  crontab -l > "$OUT/persistence/crontab.original" 2>/dev/null
  if matches "$(cat "$OUT/persistence/crontab.original")"; then add_entry cron "$OUT/persistence/crontab.original" "crontab"; fi
fi
say ""
say "== persistence =="
[[ $FOUND -eq 0 ]] && say "  none matched" || { while IFS=$'\t' read -r k w n; do say "  [$k] $n  ($w)"; done < "$OUT/persistence/entries.tsv"; }
event persistence "entries=$FOUND"

say ""
say "== artifacts =="
ART=0
for exe in "${EXES[@]}"; do
  dir="$(dirname "$exe")"
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    cp -a -- "$f" "$OUT/evidence/artifacts/" 2>/dev/null && ART=$((ART+1))
    sha256sum "$f" >> "$OUT/evidence/hashes.txt" 2>/dev/null
  done < <(find "$dir" -maxdepth 1 -type f \( -name '*.log' -o -name '*.db' -o -name '*.sqlite*' -o -name '*.ini' \
            -o -name '*.json' -o -name '*.cfg' \) -size -20M 2>/dev/null | head -40)
done
say "  files copied: $ART"

if [[ $APPLY -eq 0 ]]; then
  say ""
  say "DRY RUN complete. Nothing was changed. Re-run with --apply to execute."
  event dryrun "artifacts=$ART"
  bash -c 'true'  # keep reported state honest: no mutation happened
  exit 0
fi

# ---------------------------------------------------------------- 1. suspend, children first
say ""
say "[1] suspending ${#TREE[@]} process(es), children first"
SUSPENDED=(); FAILED=0
for pid in "${TREE[@]}"; do
  if kill -STOP "$pid" 2>/dev/null; then
    state="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)"
    if [[ "$state" == "T" || "$state" == "t" ]]; then
      SUSPENDED+=("$pid"); say "  suspended $pid ($(cat "/proc/$pid/comm" 2>/dev/null)) - verified state T"
    else
      say "  signal accepted but state is '$state' for $pid"; FAILED=$((FAILED+1))
    fi
  else
    say "  could not suspend $pid (permissions or protected process)"; FAILED=$((FAILED+1))
  fi
done
event suspend "suspended=${#SUSPENDED[@]} failed=$FAILED"

# ---------------------------------------------------------------- 2. de-persist
say ""
say "[2] removing persistence (after suspension, so nothing respawns it)"
while IFS=$'\t' read -r kind where name; do
  case "$kind" in
    systemd)
      unit="$name"
      if systemctl disable --now "$unit" >/dev/null 2>&1; then say "  disabled $unit"
      elif [[ "$where" == "$HOME"* ]]; then systemctl --user disable --now "$unit" >/dev/null 2>&1 \
        && say "  disabled (user) $unit" || say "  FAILED to disable $unit"
      else say "  FAILED to disable $unit"; fi ;;
    autostart)
      mv -- "$where" "$OUT/persistence/" 2>/dev/null && say "  autostart entry moved: $name" || say "  FAILED to move $name" ;;
    cron)
      grep -v -F -x -f <(while IFS= read -r line; do printf '%s\n' "$line"; done < <(grep -o '[^ ]*' "$where" 2>/dev/null | grep -F -e "$(basename "${EXES[0]}")")) \
        "$where" > "$OUT/persistence/crontab.new" 2>/dev/null
      if crontab "$OUT/persistence/crontab.new" 2>/dev/null; then say "  crontab rewritten (original kept)"
      else say "  FAILED to rewrite crontab"; fi ;;
  esac
done < <(cat "$OUT/persistence/entries.tsv" 2>/dev/null)

# ---------------------------------------------------------------- 3. quarantine
say ""
say "[3] quarantining install directories"
QUAR=0
: > "$OUT/persistence/renames.tsv"
for exe in "${EXES[@]}"; do
  dir="$(dirname "$exe")"
  if is_refused_dir "$dir"; then
    say "  REFUSED to rename $dir: it is a system directory, not an application directory"; continue
  fi
  [[ "$dir" == *".quarantined" ]] && { say "  already quarantined: $dir"; continue; }
  new="$dir.quarantined"
  if mv -- "$dir" "$new" 2>/dev/null; then
    printf '%s\t%s\n' "$dir" "$new" >> "$OUT/persistence/renames.tsv"
    QUAR=$((QUAR+1)); say "  $dir -> $new"
  else
    say "  FAILED to quarantine $dir (in use, permissions, or read-only filesystem)"
  fi
done
event quarantine "dirs=$QUAR"

# ---------------------------------------------------------------- 4. network
say ""
say "[4] blocking network for the quarantined paths"
RULES=0
while IFS= read -r ip; do
  [[ -z "$ip" || "$ip" == "Local" ]] && continue
  if command -v nft >/dev/null 2>&1 && nft add rule inet filter output ip daddr "$ip" drop 2>/dev/null; then
    RULES=$((RULES+1)); say "  nft drop $ip"
  elif command -v iptables >/dev/null 2>&1 && iptables -I OUTPUT -d "$ip" -j DROP 2>/dev/null; then
    RULES=$((RULES+1)); say "  iptables drop $ip"
  else
    say "  FAILED to block $ip (no usable firewall backend); recorded, not assumed"
  fi
done < <(awk '{print $6}' "$OUT/evidence/sockets.txt" 2>/dev/null | cut -d: -f1 | sort -u)
say "  rules installed: $RULES"

# ---------------------------------------------------------------- 5. read-only containment
say ""
say "[5] making quarantined copies read-only"
while IFS=$'\t' read -r old new; do
  chmod -R a-w -- "$new" 2>/dev/null && say "  read-only: $new" || say "  could not change permissions on $new"
done < "$OUT/persistence/renames.tsv" 2>/dev/null

# ---------------------------------------------------------------- restore + manifest
cat > "$OUT/RESTORE.sh" <<RESTORE
#!/usr/bin/env bash
# RESTORE.sh - generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by crush-klog.sh
# Reverses this run. Idempotent: safe to run twice. Run with the same privileges as the crush.
set -uo pipefail
echo "restoring from $OUT"
RESTORE
printf 'for pid in %s; do kill -CONT "$pid" 2>/dev/null && echo "  resumed $pid"; done\n' \
  "${SUSPENDED[*]:-}" >> "$OUT/RESTORE.sh"
{
  while IFS=$'\t' read -r old new; do
    printf 'chmod -R u+w %q 2>/dev/null; [[ -d %q ]] && mv -- %q %q && echo "  restored %s"\n' \
      "$new" "$new" "$new" "$old" "$old"
  done < "$OUT/persistence/renames.tsv" 2>/dev/null
  while IFS=$'\t' read -r kind where name; do
    [[ "$kind" == "autostart" ]] || continue
    # The recorded path, not $HOME: a restore run by another operator (or as root) has a different
    # HOME, and the entry would silently land in the wrong profile.
    printf 'mv -- %q %q 2>/dev/null && echo "  autostart restored: %s"\n' "$OUT/persistence/$name" "$where" "$name"
  done < "$OUT/persistence/entries.tsv" 2>/dev/null
  [[ -f "$OUT/persistence/crontab.original" ]] && \
    printf 'crontab %q 2>/dev/null && echo "  crontab restored"\n' "$OUT/persistence/crontab.original"
  while IFS=$'\t' read -r kind where name; do
    [[ "$kind" == "systemd" ]] || continue
    printf 'systemctl enable --now %q >/dev/null 2>&1 && echo "  unit enabled: %s"\n' "$name" "$name"
  done < "$OUT/persistence/entries.tsv" 2>/dev/null
  while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" == "Local" ]] && continue
    printf 'nft delete rule inet filter output ip daddr %q drop 2>/dev/null; iptables -D OUTPUT -d %q -j DROP 2>/dev/null; echo "  rule removed: %s"\n' "$ip" "$ip" "$ip"
  done < <(awk '{print $6}' "$OUT/evidence/sockets.txt" 2>/dev/null | cut -d: -f1 | sort -u)
} >> "$OUT/RESTORE.sh"
cat >> "$OUT/RESTORE.sh" <<'RESTORE'
echo "done. The clock was never changed by this tool."
RESTORE
chmod 0700 "$OUT/RESTORE.sh"

( cd "$OUT" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256 2>/dev/null )
event manifest "$(wc -l < "$OUT/MANIFEST.sha256" 2>/dev/null || echo 0) files"

say ""
say "== summary =="
say "suspended          : ${#SUSPENDED[@]} (of ${#TREE[@]} in tree, $FAILED failed)"
say "persistence hits   : $FOUND handled"
say "directories moved  : $QUAR"
say "network rules      : $RULES"
say "artifacts kept     : $ART files, $CAPTURED binaries"
say ""
say "Undo: $OUT/RESTORE.sh"
if [[ $FAILED -gt 0 || $QUAR -eq 0 ]]; then
  say "PARTIAL: some steps failed. Read report.txt before declaring this contained." >&2
  exit 3
fi
exit 0
