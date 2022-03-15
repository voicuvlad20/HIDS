BPF_PROGRAM = "muie la astia care se uita la live"
BPF_PROGRAM = BPF_PROGRAM + "\n"
system_calls = [("write", 1), ("read", 2), ("raresEZeu", 69420)]

for call in system_calls:
    function = """int %s(struct pt_regs *ctx) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo = %i;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}""" %(call[0], call[1])   
    BPF_PROGRAM = BPF_PROGRAM + function

print(BPF_PROGRAM)