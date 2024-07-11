#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include <linux/perf_event.h>

extern int errno;

static void print_stack(__u32 *captured_stackid_key, __u64 count, int trace_fd) {
  __u64 ip[PERF_MAX_STACK_DEPTH] = {};

  if (bpf_map_lookup_elem(trace_fd, captured_stackid_key, ip) != 0) {
    printf("Could not find a stack trace for the key %p\n", captured_stackid_key);
  } else {
    int i = 0;
    for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
      printf("ip: %p\n", (void *)ip[i]);
  }
}

int main() {

  struct bpf_object *object = bpf_object__open_file("build/bpf_st.o", NULL);

  if (object == NULL) {
    perror("Failed to load the object");
    return 0;
  }
  int loaded = bpf_object__load(object);

  if (loaded < 0) {
    perror("Failed to load the object");
    return 0;
  }

  struct bpf_program *program =
      bpf_object__find_program_by_name(object, "generate_bt");
  if (!program) {
    bpf_object__close(object);
    perror("Failed to load the object");
    return 0;
  }

  struct bpf_link *link = bpf_program__attach(program);
  if (!link) {
    bpf_object__close(object);
    perror("Failed to attach the bpf error detector");
    return 0;
  }

  int backtrace_stacks_fd =
      bpf_object__find_map_fd_by_name(object, "backtrace_stacks");
  int backtrace_counts_fd =
      bpf_object__find_map_fd_by_name(object, "backtrace_counts");

  sleep(15);

  __u32 stackid = 0;
  __u32 stackid_next = 0;

  while (bpf_map_get_next_key(backtrace_counts_fd, &stackid, &stackid_next) ==
         0) {
    __u64 stack_counts;
    bpf_map_lookup_elem(backtrace_counts_fd, &stackid_next, &stack_counts);
    print_stack(&stackid_next, stack_counts, backtrace_stacks_fd);
    bpf_map_delete_elem(backtrace_counts_fd, &stackid_next);
    stackid = stackid_next;
  }

  stackid = stackid_next = 0;
  /* clear stack map */
  while (bpf_map_get_next_key(backtrace_stacks_fd, &stackid, &stackid_next) ==
         0) {
    bpf_map_delete_elem(backtrace_stacks_fd, &stackid_next);
    stackid = stackid_next;
  }
}
