from bcc import BPF


def create_print_key_read_event(b):
    def print_key_read_event(cpu, data, size):
        event = b["keyctl_read_events"].event(data)
        print(f"key buffer from keyctl_read(): {event.data}")

    return print_key_read_event


def main():
    fh = open("keyctl_snoop.c")
    program = fh.read()
    fh.close()
    b = BPF(text=program)

    b.attach_kprobe(event=b.get_syscall_fnname("keyctl"), fn_name="syscall__keyctl")
    b.attach_kretprobe(event=b.get_syscall_fnname("keyctl"), fn_name="on_return")

    print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
    callback = create_print_key_read_event(b)
    b["keyctl_read_events"].open_perf_buffer(callback)

    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
        b.perf_buffer_poll()


if __name__ == "__main__":
    main()
