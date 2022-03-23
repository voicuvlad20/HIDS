from math import prod
from bcc import BPF
import psycopg2
import pandas as pd
import pickle
import time
import os

MAIN_BPF = r"""
#include <linux/sched.h>
//create a data structure which takes information about systemcalls(it is created in kernel and it is send in user space through events)
struct data_t {
    //id saw in user space
    u32 uid;
    //program pid
    u32 pid;
    //systemCall number which makes the difference visible between systemcalls 
    u32 syscallNo;
    //command name executed
    char comm[TASK_COMM_LEN];

};

//communication channel between kernel and user space
BPF_PERF_OUTPUT(events);
"""
MAIN_BPF = MAIN_BPF + "\n"

conn = psycopg2.connect(host="localhost", database="mydb", user="vladvoicu", password="123")
cur = conn.cursor()
        
# execute a statement
print('PostgreSQL database version:')
cur.execute('SELECT version()')

# display the PostgreSQL database server version
db_version = cur.fetchone()
print(db_version)

# close the communication with the PostgreSQL
cur.close()

system_calls = [("read", 182), ("write", 306), ("open", 163), ("close", 24), ("newstat", 260), ("newfstat", 61), ("newlstat", 127), ("poll", 171), ("lseek", 124), 
("mmap", 139), ("mprotect", 143), ("munmap", 158), ("brk", 12), ("rt_sigaction", 199), ("rt_sigprocmask", 201), ("ioctl", 109), ("pwrite64", 179), ("readv", 186), 
("writev", 307), ("access", 4), ("pipe", 168), ("select", 217), ("sched_yield", 216), ("mremap", 150), ("msync", 155), ("mincore", 132), ("madvise", 129), ("shmget", 252), 
("shmat", 249), ("shmctl", 250), ("dup", 28), ("dup2", 29), ("pause", 165), ("nanosleep", 159), ("getitimer", 81), ("alarm", 8), ("setitimer", 236), ("getpid", 85),
("sendfile64", 39), ("socket", 257), ("connect", 25), ("accept", 2), ("sendto", 226), ("recvfrom", 189), ("sendmsg", 225), ("recvmsg", 191), ("shutdown", 253), ("bind", 11),
("listen", 119), ("getsockname", 93), ("getpeername", 82), ("socketpair", 258), ("setsockopt", 245), ("getsockopt", 94), ("wait4", 304), ("kill", 114), ("newuname", 58),
("semget", 219), ("semop", 220), ("semctl", 218), ("shmdt", 251), ("msgget", 152), ("msgsnd", 154), ("msgrcv", 153), ("msgctl", 151), ("fcntl", 52), ("flock", 57),
("fsync", 66), ("fdatasync", 54), ("truncate", 287), ("ftruncate", 67), ("getdents", 75), ("getcwd", 74), ("chdir", 15), ("fchdir", 47), ("rename", 194), ("mkdir", 133),
("rmdir", 198), ("creat", 26), ("link", 117), ("unlink", 293), ("symlink", 266), ("readlink", 184), ("chmod", 16), ("fchmod", 48), ("chown", 17), ("fchown", 50),
("lchown", 115), ("umask", 289), ("gettimeofday", 96), ("getrlimit", 90), ("sysinfo", 272), ("times", 285), ("ptrace", 178), ("getuid", 97), ("syslog", 273),
("getgid", 79), ("setgid", 233), ("geteuid", 78), ("getegid", 77), ("setpgid", 237), ("getppid", 86), ("getpgrp", 84), ("setsid", 244),
("setreuid", 242), ("setregid", 239), ("getgroups", 80), ("setgroups", 234), ("setresuid", 241), ("getresuid", 89), ("setresgid", 240), ("getresgid", 88), ("getpgid", 83), 
("setfsuid", 232), ("setfsgid", 231), ("getsid", 92), ("capget", 13), ("capset", 14), ("rt_sigsuspend", 204), 
("sigaltstack", 254), ("utime", 298), ("mknod", 135), ("ustat", 297), ("statfs", 262), ("fstatfs", 64), ("sysfs", 133), ("getpriority", 87), 
("setpriority", 238), ("sched_setparam", 214), ("sched_getparam", 210), ("sched_getscheduler", 215), ("sched_get_priority_max", 207), ("sched_get_priority_min", 208), ("sched_rr_get_interval", 212), ("mlock", 137), 
("munlock", 156), ("mlockall", 138), ("munlockall", 157), ("vhangup", 302), ("modify_ldt", 148), ("prctl", 173), ("arch_prctl", 152), 
("adjtimex", 7), ("setrlimit", 243), ("chroot", 18), ("sync", 268), ("acct", 5), ("settimeofday", 246), ("mount", 141), ("umount", 290), ("swapon", 265), 
("swapoff", 264), ("reboot", 187), ("sethostname", 235), ("setdomainname", 230), ("init_module", 99), ("delete_module", 27), ("quotactl", 181), ("gettid", 95),
("readahead", 183), ("setxattr", 248), ("lsetxattr", 126), ("fsetxattr", 60), ("getxattr", 98), ("lgetxattr", 116), ("fgetxattr", 55), ("listxattr", 120), ("llistxattr", 121), 
("flistxattr", 56), ("removexattr", 193), ("lremovexattr", 123), ("fremovexattr", 59), ("tkill", 286), ("time", 276), ("futex", 69), 
("io_setup", 107), ("io_destroy", 105), ("io_getevents", 106), ("io_submit", 108), ("io_cancel", 104), ("lookup_dcookie", 122), ("epoll_create", 31), ("remap_file_pages", 192), ("getdents64", 76), 
("set_tid_address", 229), ("restart_syscall", 197), ("semtimedop", 221), ("fadvise64", 42), ("timer_create", 277), ("timer_settime", 281), ("timer_gettime", 280), ("timer_getoverrun", 279), ("timer_delete", 278), 
("clock_settime", 22), ("clock_gettime", 20), ("clock_getres", 19), ("clock_nanosleep", 21), ("exit_group", 40), ("epoll_wait", 35), ("epoll_ctl", 33), ("tgkill", 275), ("utimes", 300), 
("mbind", 130), ("set_mempolicy", 227), ("get_mempolicy", 71), ("mq_open", 146), ("mq_unlink", 149), ("mq_timedsend", 148), ("mq_timedreceive", 147), ("mq_notify", 145), ("mq_getsetattr", 144), 
("kexec_load", 112), ("waitid", 305), ("add_key", 6), ("request_key", 196), ("keyctl", 113), ("ioprio_set", 111), ("ioprio_get", 110), ("inotify_init", 101), ("inotify_add_watch", 100), 
("inotify_rm_watch", 103), ("migrate_pages", 131), ("openat", 164), ("mkdirat", 134), ("mknodat", 136), ("fchownat", 51), ("futimesat", 70), ("newfstatat", 160), ("unlinkat", 294), 
("renameat", 195), ("linkat", 118), ("symlinkat", 267), ("readlinkat", 185), ("fchmodat", 49), ("faccessat", 41), ("pselect6", 177), ("ppoll", 172), ("unshare", 295), 
("set_robust_list", 228), ("get_robust_list", 72), ("splice", 259), ("tee", 274), ("sync_file_range", 269), ("vmsplice", 303), ("move_pages", 142), ("utimensat", 299), ("epoll_pwait", 34), 
("signalfd", 255), ("timerfd_create", 282), ("eventfd", 36), ("fallocate", 44), ("timerfd_settime", 284), ("timerfd_gettime", 283), ("accept4", 3), ("signalfd4", 256), ("eventfd2", 37), 
("epoll_create1", 32), ("dup3", 30), ("pipe2", 169), ("inotify_init1", 102), ("preadv", 175), ("pwritev", 180), ("rt_tgsigqueueinfo", 206), ("recvmmsg", 190), 
("fanotify_init", 45), ("fanotify_mark", 46), ("prlimit64", 176), ("name_to_handle_at", 282), ("open_by_handle_at", 283), ("clock_adjtime", 284), ("syncfs", 285), ("sendmmsg", 286), ("setns", 287), 
("getcpu", 73), ("process_vm_readv", 400), ("process_vm_writev", 401), ("kcmp", 402), ("finit_module", 403), ("sched_getattr", 404), ("renameat2", 405), ("seccomp", 406), 
("getrandom", 407), ("memfd_create", 408), ("kexec_file_load", 409), ("bpf", 410), ("membarrier", 411), ("mlock2", 412), ("copy_file_range", 413), ("preadv2", 414),
("pwritev2", 415), ("pkey_mprotect", 416), ("pkey_alloc", 417), ("pkey_free", 418)] 

#for each system call there will be this function with the system call and its number
for call in system_calls:
    function = r"""
    #include <linux/sched.h>
    int %s(struct pt_regs *ctx) {
        //initialize the data structure
        struct data_t data = {};
        //I take the userID and the pid from the system calls
        data.uid = bpf_get_current_uid_gid();
        //bit operation 
        data.pid = bpf_get_current_pid_tgid() >> 32;
        //take the corresponding number for each system call from the list of pairs
        data.syscallNo = %i;
        //I take the command name
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        //send the data structure in user space through perf_submit
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }""" %(call[0], call[1])
    MAIN_BPF = MAIN_BPF + function


#load the script from C in kernel
bpf = BPF(text=MAIN_BPF)

#for each function, it link the function from C with the system call 
for system_call_name in system_calls:
    bpf.attach_kprobe(event=bpf.get_syscall_fnname(system_call_name[0]), fn_name = system_call_name[0])

syscallNo = ""
comm_list = []
command_dict = {}

def print_event(cpu, data, size):
    global comm_list
    global command_dict
    global process_df
    global model

    #when an event is made, receive the response in the variable(this is where the system calls are remembered)
    event = bpf["events"].event(data)

    #fac dictionar ca sa nu imi arate acelasi sys call de la ac program
    if command_dict.get(event.pid,0) < 50:
       command_dict[event.pid] = command_dict.get(event.pid, 0) + 1
    #formatat sa scoata event ul din spatiul userlui, numele comenzii, dictionarul, event pid
    #print("PID=%-6d SYSCALL=%-6d" % (event.pid, event.syscallNo))

    if event.pid in process_df['PID'].unique():
        process_df.loc[(process_df['PID'] == event.pid), event.syscallNo] = process_df[event.syscallNo] + 1
    else:
        process_df = process_df.append({'PID':event.pid,event.syscallNo:1}, ignore_index=True).fillna(0)
    process_df.to_csv('test.csv', index=False)
    X = process_df[process_df['PID'] == event.pid].drop(['PID','prediction'], axis=1).astype(int).values
    process_df['prediction'] = model.predict(X)
    #if len(process_df[process_df['prediction'] == 1]) > 0:
        #print("Attack")
        #exit()
    #else:
        #print("Not Attack")
    #print("---------------------------------------")
    #time.sleep(0.2)

    if len(process_df[process_df['prediction'] == 1]) > 0:
        print("Attack")
        
    
    #if prediction == 0:
        #print("Not attack")
    #else:
        #print("Attack")
    #print("---------------------------------------")
    #time.sleep(0.2)

process_df = pd.DataFrame(columns = [i for i in range(0, 419)] + ['PID','prediction'])
model = pickle.load(open("frequency_model.pkl", "rb"))
bpf["events"].open_perf_buffer(print_event)

while 1:
 try:
    bpf.perf_buffer_poll()
 except KeyboardInterrupt:
    print("Interrupted")


#sa fac metoda sa capturez toate systemcallurile, sa le salvez undeva si cumva pt ca sunt multe
#sa vad cum le dau retreive(sa vad cum arata system callurile si in ce ordine ca sa vad daca e atatc)
#fol system de ml ca sa le verifice

#care sunt inputurile pt functiile de mai sus

#sa rulez virusi intr un sandbox sau docker si sa le iau trace ul si sa antrenez algoritmul cu alea
#sau sa teztes algoritmul cu baza de date 

#pt baza de date imi trb procesul, numarulSysCall si numeleSysCall
#caut paper uri care testeaza pe alfa-ld ca sa gasesc librarii de ml

#in loc de ml pot sa folosesc lstm(long short term memory) sau elm care ia ia date si prezice 