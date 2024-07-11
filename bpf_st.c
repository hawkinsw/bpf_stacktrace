#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10000);
} backtrace_stacks SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1000);
} backtrace_counts SEC(".maps");

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

SEC("tracepoint/sched/sched_process_exit")
int generate_bt(void *ctx) {
  __u64 *val, one = 1;

  __u64 kernstack = bpf_get_stackid(ctx, &backtrace_stacks, KERN_STACKID_FLAGS);
  if ((int)kernstack < 0) {
    char error_message[] = "Error: %d\n";
    bpf_trace_printk(error_message, sizeof(error_message), kernstack);
    return 0;
  }

  val = bpf_map_lookup_elem(&backtrace_counts, &kernstack);
  if (val)
    (*val)++;
  else
    bpf_map_update_elem(&backtrace_counts, &kernstack, &one, BPF_NOEXIST);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
