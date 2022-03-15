from bcc import BPF

BPF_PROGRAM = r"""
#include <linux/sched.h>
//creez o structura de date care retine inf despre system call(e creat in kernel si e dus in user space prin event)
struct data_t {
    //pid ul programului
    u32 pid;
    //id ul vazut in spatiul userului
    u32 uid;
    //numele comenzii
    char comm[TASK_COMM_LEN];
    //nr pe care atribui ca sa faci dif intre system calluri
    u32 syscallNo;
};

//canalul de comunicare dintre kernel si user space
BPF_PERF_OUTPUT(events);
//pt fiecare system call trb sa am cate o functie si numele functie o sa fie numele din system call
int clone(struct pt_regs *ctx) {
    //initializez structura de date
    struct data_t data = {};
    //iau user id si pid din system call uri
    data.uid = bpf_get_current_uid_gid();
    //operatie pe bit
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    //conventie
    data.syscallNo=0;
    //primesc numele comenzii(numele programului)
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //trimit structura de date in user space prin perf
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int mmap(struct pt_regs *ctx) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=2;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int read(struct pt_regs *ctx) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=3;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
int write(struct pt_regs *ctx) {
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();
    if (data.uid != 0)
        return 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
     #ifdef FILTER_PID
    if (data.pid == FILTER_PID)
        return 0;
    #endif
    data.syscallNo=4;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


#incarca programul scris in c in kernel
bpf = BPF(text=BPF_PROGRAM)
#pt fiecare functie leaga functia din c cu system call
bpf.attach_kprobe(event=bpf.get_syscall_fnname("clone"), fn_name="clone")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("mmap"), fn_name="mmap")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="execve")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="read")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("write"), fn_name="write")



start = 0
syscallNo = ""
prevsyscall = -1
prevtime = 0

iteration = 0
elapsed_iter = 0

print("file opened")
comm_list = []
command_dict = {}
lastSyscall = ''
def print_event(cpu, data, size):
    global start
    global iteration
    global prevtime
    global elapsed_iter
    global writer
    global comm_list
    global command_dict

    #cand se face un event primesc raspuns in variabila asta(aici sunt retinute system call urile)
    event = bpf["events"].event(data)
    #pt fiecare numar, le am atribuit numele
    if event.syscallNo == 0:
        syscallNo = "clone"
    if event.syscallNo == 1:
        syscallNo = "mmap"
    if event.syscallNo == 2:
        syscallNo = "execve"
    if event.syscallNo == 3:
        syscallNo = "read"
    if event.syscallNo == 4:
        syscallNo = "write"

    #fac dictionar ca sa nu imi arate acelasi sys call de la ac program
    if command_dict.get(event.pid,0) < 50:
        command_dict[event.pid] = command_dict.get(event.pid, 0) + 1
        #formatat sa scoata event ul din spatiul userlui, numele comenzii, dictionarul, event pid
        print("%-6d %-16s %-6d %-6d %s %-6d" % (event.uid, event.comm, command_dict.get(event.pid, 0), event.pid,
                                                syscallNo, len(command_dict)))

bpf["events"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
