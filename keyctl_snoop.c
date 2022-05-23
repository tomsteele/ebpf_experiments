#include <linux/in.h>
#include <linux/ptrace.h>

#define MAX_KEY 4096

struct keyctl_read_args {
    char *buff;
    u64 buff_len;
};

struct key_data {
    char data[MAX_KEY];
};

// Used to store arguments on call and handle on return.
BPF_HASH(keyctl_read_arguments, u32, struct keyctl_read_args);

// The stack size is limited in ebpf programs. This is
// way to store our data off the stack.
BPF_PERCPU_ARRAY(key_data, struct key_data, 1);

BPF_PERF_OUTPUT(keyctl_read_events);

int syscall__keyctl(struct pt_regs *ctx, int operation, __kernel_ulong_t arg2, char *buff, u64 buff_len) {
    // KEYCTL_READ == 0x0B.
    if (operation != 0x0B) {
        return 0;
    }
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    struct keyctl_read_args args = {buff, buff_len};
    keyctl_read_arguments.update(&pid, &args);
    bpf_trace_printk("keyctl_read() - operation %d \n",operation);
    return 0;
}

int on_return(struct pt_regs *ctx) {
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    struct keyctl_read_args *args = keyctl_read_arguments.lookup(&pid);
    // We didn't get a read yet, could be another keyctl call.
    if (!args) {
        return 0;
    }
    if (args->buff_len == 0) {
        return 0;
    }
    keyctl_read_arguments.delete(&pid);

    // We always use the first item in the PERCPU_ARRAY to store our event data.
    u32 zero = 0;
    struct key_data *data = key_data.lookup(&zero);
    if (!data) {
        return 0;
    }
    if (args->buff_len > MAX_KEY) {
        return 0;
    }
    unsigned int data_len = args->buff_len;
    bpf_probe_read_user(data->data, data_len, (void *)args->buff);
    keyctl_read_events.perf_submit(ctx, data, data_len);
    return 0;
}
