#!/usr/bin/env bash
# Names exactly which probe in mem_copies.bt bpftrace rejects (run as root).
set -u
probes=(
  "kprobe:_copy_to_user"
  "kprobe:_copy_from_user"
  "tracepoint:syscalls:sys_enter_sendmsg"
  "tracepoint:syscalls:sys_enter_recvmsg"
  "tracepoint:syscalls:sys_enter_splice"
  "tracepoint:syscalls:sys_enter_poll"
  "tracepoint:syscalls:sys_enter_ppoll"
  "tracepoint:syscalls:sys_enter_io_uring_enter"
)
echo "bpftrace $(bpftrace --version 2>&1 | head -1)"
for p in "${probes[@]}"; do
  err=$(timeout 8 bpftrace -e "$p { @=count(); } interval:s:1 { exit(); }" 2>&1 >/dev/null)
  if echo "$err" | grep -qiE 'error|fail|blacklist|denied|not found|No such'; then
    echo "  BAD  $p"
    echo "       $(echo "$err" | grep -iE 'error|fail|blacklist|denied|not' | head -1)"
  else
    echo "  ok   $p"
  fi
done
