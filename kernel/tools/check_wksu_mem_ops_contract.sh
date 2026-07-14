#!/bin/sh
set -eu

kernel_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
header="$kernel_dir/supercalls.h"
source="$kernel_dir/supercalls.c"

require_fixed()
{
	needle=$1
	file=$2
	if ! grep -Fq -- "$needle" "$file"; then
		echo "missing WKSU memory-ops contract: $needle" >&2
		exit 1
	fi
}

require_fixed "#define WKSU_MEM_OPS_VERSION 1" "$header"
require_fixed "#define WKSU_MEM_OP_MAX_COUNT 256" "$header"
require_fixed "#define WKSU_MEM_OP_READ_CHAIN 2" "$header"
require_fixed "struct wksu_mem_op" "$header"
require_fixed "struct wksu_mem_ops_cmd" "$header"
require_fixed "#define KSU_IOCTL_MEM_OPS_V1 _IOWR('K', 33, struct wksu_mem_ops_cmd)" "$header"
require_fixed "static int do_mem_ops" "$source"
require_fixed ".cmd = KSU_IOCTL_MEM_OPS_V1" "$source"
require_fixed "wksu_normalize_remote_addr(next_addr, &chain_addr)" "$source"
require_fixed "op->done = done" "$source"
require_fixed "cmd.completed = completed" "$source"
require_fixed "#define WKSU_MEM_RW_MAX_LEN" "$source"
require_fixed "cmd.len > WKSU_MEM_RW_MAX_LEN" "$source"
require_fixed "cmd.write > 1" "$source"
require_fixed "check_add_overflow(cmd.addr" "$source"

echo "WKSU memory-ops contract present"
