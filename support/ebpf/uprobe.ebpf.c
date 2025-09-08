#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

typedef struct GenericParam {
  u64 correlation_id;
} GenericParam;

bpf_map_def SEC("maps") generic_params = {
  .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(GenericParam),
  .max_entries = 1,
};

static struct GenericParam zero_generic_param = {};

// uprobe__generic serves as entry point for uprobe based profiling.
SEC("uprobe/generic")
int uprobe__generic(void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u32 zero            = 0;
  GenericParam *param = bpf_map_lookup_elem(&generic_params, &zero);
  if (!param) {
    return 0;
  }

  // Required as otherwise the reset will override the value.
  GenericParam paramData = *param;

  if (bpf_map_update_elem(&generic_params, &zero, &zero_generic_param, BPF_ANY) < 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, TRACE_UPROBE, pid, tid, ts, 0, paramData.correlation_id);
}
