#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

typedef struct GenericParam {
  u64 correlation_id;
} GenericParam;

struct generic_params_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, GenericParam);
  __uint(max_entries, 1);
} generic_params SEC(".maps");

static struct GenericParam zero_generic_param = {};

static EBPF_INLINE int probe__generic(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts              = bpf_ktime_get_ns();
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

  return collect_trace(ctx, TRACE_PROBE, pid, tid, ts, 0, paramData.correlation_id);
}

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  return probe__generic(ctx);
}
