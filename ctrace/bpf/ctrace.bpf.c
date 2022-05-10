// +build ignore

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/bpf.h>



#include <linux/fs.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/socket.h>



#define MAX_PERCPU_BUFSIZE  (1 << 15)     // This value is actually set by the kernel as an upper bound
#define MAX_STRING_SIZE     4096          // Choosing this value to be the same as PATH_MAX
#define MAX_STR_ARR_ELEM    40            // String array elements number should be bounded due to instructions limit
#define MAX_PATH_PREF_SIZE  64            // Max path prefix should be bounded due to instructions limit


// buffer overview: submit---string---file
#define SUBMIT_BUF_IDX      0
#define STRING_BUF_IDX      1
#define FILE_BUF_IDX        2
#define MAX_BUFFERS         3

#define CONFIG_SHOW_SYSCALL     0
#define CONFIG_EXEC_ENV         1
#define CONFIG_CAPTURE_FILES    2
#define CONFIG_EXTRACT_DYN_CODE 3

#define NONE_T        0UL
#define INT_T         1UL
#define UINT_T        2UL
#define LONG_T        3UL
#define ULONG_T       4UL
#define OFF_T_T       5UL
#define MODE_T_T      6UL
#define DEV_T_T       7UL
#define SIZE_T_T      8UL
#define POINTER_T     9UL
#define STR_T         10UL
#define STR_ARR_T     11UL
#define SOCKADDR_T    12UL
#define ALERT_T       13UL
#define TYPE_MAX      255UL

#define TAG_NONE           0UL
#define TAG_FD             1UL
#define TAG_FILENAME       2UL
#define TAG_PATHNAME       3UL
#define TAG_ARGV           4UL
#define TAG_ENVP           5UL
#define TAG_DEV            6UL
#define TAG_INODE          7UL
#define TAG_DIRFD          8UL
#define TAG_FLAGS          9UL
#define TAG_CAP            10UL
#define TAG_SYSCALL        11UL
#define TAG_COUNT          12UL
#define TAG_POS            13UL
#define TAG_ALERT          14UL
#define TAG_MODE           15UL
#define TAG_ADDR           16UL
#define TAG_LENGTH         17UL
#define TAG_PROT           18UL
#define TAG_OFFSET         19UL
#define TAG_PKEY           20UL
#define TAG_NAME           21UL
#define TAG_OLDFD          22UL
#define TAG_NEWFD          23UL
#define TAG_DOMAIN         24UL
#define TAG_TYPE           25UL
#define TAG_PROTOCOL       26UL
#define TAG_REQUEST        27UL
#define TAG_PID            28UL
#define TAG_SIG            29UL
#define TAG_SOCKFD         30UL
#define TAG_BACKLOG        31UL
#define TAG_OPTION         32UL
#define TAG_ARG2           33UL
#define TAG_ARG3           34UL
#define TAG_ARG4           35UL
#define TAG_ARG5           36UL
#define TAG_DATA           37UL
#define TAG_LOCAL_IOV      38UL
#define TAG_LIOVCNT        39UL
#define TAG_REMOTE_IOV     40UL
#define TAG_RIOVCNT        41UL
#define TAG_MODULE_IMAGE   42UL
#define TAG_LEN            43UL
#define TAG_PARAM_VALUES   44UL
#define TAG_TARGET         45UL
#define TAG_NEWDIRFD       46UL
#define TAG_LINKPATH       47UL
#define TAG_SOURCE         48UL
#define TAG_FILESYSTEMTYPE 49UL
#define TAG_MOUNTFLAGS     50UL
#define TAG_UID            51UL
#define TAG_GID            52UL
#define TAG_FSUID          53UL
#define TAG_FSGID          54UL
#define TAG_RUID           55UL
#define TAG_EUID           56UL
#define TAG_RGID           57UL
#define TAG_EGID           58UL
#define TAG_SUID           59UL
#define TAG_SGID           60UL
#define TAG_OWNER          61UL
#define TAG_GROUP          62UL

#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 0))
#define RHEL_RELEASE_GT_8_0
#endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
#error Minimal required kernel version is 4.18
#endif

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);         \
        _val;                                                           \
    })



/*==================================== ENUMS =================================*/

enum event_id {
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_STAT,
    SYS_FSTAT,
    SYS_LSTAT,
    SYS_POLL,
    SYS_LSEEK,
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_MUNMAP,
    SYS_BRK,
    SYS_RT_SIGACTION,
    SYS_RT_SIGPROCMASK,
    SYS_RT_SIGRETURN,
    SYS_IOCTL,
    SYS_PREAD64,
    SYS_PWRITE64,
    SYS_READV,
    SYS_WRITEV,
    SYS_ACCESS,
    SYS_PIPE,
    SYS_SELECT,
    SYS_SCHED_YIELD,
    SYS_MREMAP,
    SYS_MSYNC,
    SYS_MINCORE,
    SYS_MADVISE,
    SYS_SHMGET,
    SYS_SHMAT,
    SYS_SHMCTL,
    SYS_DUP,
    SYS_DUP2,
    SYS_PAUSE,
    SYS_NANOSLEEP,
    SYS_GETITIMER,
    SYS_ALARM,
    SYS_SETITIMER,
    SYS_GETPID,
    SYS_SENDFILE,
    SYS_SOCKET,
    SYS_CONNECT,
    SYS_ACCEPT,
    SYS_SENDTO,
    SYS_RECVFROM,
    SYS_SENDMSG,
    SYS_RECVMSG,
    SYS_SHUTDOWN,
    SYS_BIND,
    SYS_LISTEN,
    SYS_GETSOCKNAME,
    SYS_GETPEERNAME,
    SYS_SOCKETPAIR,
    SYS_SETSOCKOPT,
    SYS_GETSOCKOPT,
    SYS_CLONE,
    SYS_FORK,
    SYS_VFORK,
    SYS_EXECVE,
    SYS_EXIT,
    SYS_WAIT4,
    SYS_KILL,
    SYS_UNAME,
    SYS_SEMGET,
    SYS_SEMOP,
    SYS_SEMCTL,
    SYS_SHMDT,
    SYS_MSGGET,
    SYS_MSGSND,
    SYS_MSGRCV,
    SYS_MSGCTL,
    SYS_FCNTL,
    SYS_FLOCK,
    SYS_FSYNC,
    SYS_FDATASYNC,
    SYS_TRUNCATE,
    SYS_FTRUNCATE,
    SYS_GETDENTS,
    SYS_GETCWD,
    SYS_CHDIR,
    SYS_FCHDIR,
    SYS_RENAME,
    SYS_MKDIR,
    SYS_RMDIR,
    SYS_CREAT,
    SYS_LINK,
    SYS_UNLINK,
    SYS_SYMLINK,
    SYS_READLINK,
    SYS_CHMOD,
    SYS_FCHMOD,
    SYS_CHOWN,
    SYS_FCHOWN,
    SYS_LCHOWN,
    SYS_UMASK,
    SYS_GETTIMEOFDAY,
    SYS_GETRLIMIT,
    SYS_GETRUSAGE,
    SYS_SYSINFO,
    SYS_TIMES,
    SYS_PTRACE,
    SYS_GETUID,
    SYS_SYSLOG,
    SYS_GETGID,
    SYS_SETUID,
    SYS_SETGID,
    SYS_GETEUID,
    SYS_GETEGID,
    SYS_SETPGID,
    SYS_GETPPID,
    SYS_GETPGRP,
    SYS_SETSID,
    SYS_SETREUID,
    SYS_SETREGID,
    SYS_GETGROUPS,
    SYS_SETGROUPS,
    SYS_SETRESUID,
    SYS_GETRESUID,
    SYS_SETRESGID,
    SYS_GETRESGID,
    SYS_GETPGID,
    SYS_SETFSUID,
    SYS_SETFSGID,
    SYS_GETSID,
    SYS_CAPGET,
    SYS_CAPSET,
    SYS_RT_SIGPENDING,
    SYS_RT_SIGTIMEDWAIT,
    SYS_RT_SIGQUEUEINFO,
    SYS_RT_SIGSUSPEND,
    SYS_SIGALTSTACK,
    SYS_UTIME,
    SYS_MKNOD,
    SYS_USELIB,
    SYS_PERSONALITY,
    SYS_USTAT,
    SYS_STATFS,
    SYS_FSTATFS,
    SYS_SYSFS,
    SYS_GETPRIORITY,
    SYS_SETPRIORITY,
    SYS_SCHED_SETPARAM,
    SYS_SCHED_GETPARAM,
    SYS_SCHED_SETSCHEDULER,
    SYS_SCHED_GETSCHEDULER,
    SYS_SCHED_GET_PRIORITY_MAX,
    SYS_SCHED_GET_PRIORITY_MIN,
    SYS_SCHED_RR_GET_INTERVAL,
    SYS_MLOCK,
    SYS_MUNLOCK,
    SYS_MLOCKALL,
    SYS_MUNLOCKALL,
    SYS_VHANGUP,
    SYS_MODIFY_LDT,
    SYS_PIVOT_ROOT,
    SYS_SYSCTL,
    SYS_PRCTL,
    SYS_ARCH_PRCTL,
    SYS_ADJTIMEX,
    SYS_SETRLIMIT,
    SYS_CHROOT,
    SYS_SYNC,
    SYS_ACCT,
    SYS_SETTIMEOFDAY,
    SYS_MOUNT,
    SYS_UMOUNT,
    SYS_SWAPON,
    SYS_SWAPOFF,
    SYS_REBOOT,
    SYS_SETHOSTNAME,
    SYS_SETDOMAINNAME,
    SYS_IOPL,
    SYS_IOPERM,
    SYS_CREATE_MODULE,
    SYS_INIT_MODULE,
    SYS_DELETE_MODULE,
    SYS_GET_KERNEL_SYMS,
    SYS_QUERY_MODULE,
    SYS_QUOTACTL,
    SYS_NFSSERVCTL,
    SYS_GETPMSG,
    SYS_PUTPMSG,
    SYS_AFS,
    SYS_TUXCALL,
    SYS_SECURITY,
    SYS_GETTID,
    SYS_READAHEAD,
    SYS_SETXATTR,
    SYS_LSETXATTR,
    SYS_FSETXATTR,
    SYS_GETXATTR,
    SYS_LGETXATTR,
    SYS_FGETXATTR,
    SYS_LISTXATTR,
    SYS_LLISTXATTR,
    SYS_FLISTXATTR,
    SYS_REMOVEXATTR,
    SYS_LREMOVEXATTR,
    SYS_FREMOVEXATTR,
    SYS_TKILL,
    SYS_TIME,
    SYS_FUTEX,
    SYS_SCHED_SETAFFINITY,
    SYS_SCHED_GETAFFINITY,
    SYS_SET_THREAD_AREA,
    SYS_IO_SETUP,
    SYS_IO_DESTROY,
    SYS_IO_GETEVENTS,
    SYS_IO_SUBMIT,
    SYS_IO_CANCEL,
    SYS_GET_THREAD_AREA,
    SYS_LOOOKUP_DCOOKIE,
    SYS_EPOLL_CREATE,
    SYS_EPOLL_CTL_OLD,
    SYS_EPOLL_WAIT_OLD,
    SYS_REMAP_FILE_PAGES,
    SYS_GETDENTS64,
    SYS_SET_TID_ADDRESS,
    SYS_RESTART_SYSCALL,
    SYS_SEMTIMEDOP,
    SYS_FADVISE64,
    SYS_TIMER_CREATE,
    SYS_TIMER_SETTIME,
    SYS_TIMER_GETTIME,
    SYS_TIMER_GETOVERRUN,
    SYS_TIMER_DELETE,
    SYS_CLOCK_SETTIME,
    SYS_CLOCK_GETTIME,
    SYS_CLOCK_GETRES,
    SYS_CLOCK_NANOSLEEP,
    SYS_EXIT_GROUP,
    SYS_EPOLL_WAIT,
    SYS_EPOLL_CTL,
    SYS_TGKILL,
    SYS_UTIMES,
    SYS_VSERVER,
    SYS_MBIND,
    SYS_SET_MEMPOLICY,
    SYS_GET_MEMPOLICY,
    SYS_MQ_OPEN,
    SYS_MQ_UNLINK,
    SYS_MQ_TIMEDSEND,
    SYS_MQ_TIMEDRECEIVE,
    SYS_MQ_NOTIFY,
    SYS_MQ_GETSETATTR,
    SYS_KEXEC_LOAD,
    SYS_WAITID,
    SYS_ADD_KEY,
    SYS_REQUEST_KEY,
    SYS_KEYCTL,
    SYS_IOPRIO_SET,
    SYS_IOPRIO_GET,
    SYS_INOTIFY_INIT,
    SYS_INOTIFY_ADD_WATCH,
    SYS_INOTIFY_RM_WATCH,
    SYS_MIGRATE_PAGES,
    SYS_OPENAT,
    SYS_MKDIRAT,
    SYS_MKNODAT,
    SYS_FCHOWNAT,
    SYS_FUTIMESAT,
    SYS_NEWFSTATAT,
    SYS_UNLINKAT,
    SYS_RENAMEAT,
    SYS_LINKAT,
    SYS_SYMLINKAT,
    SYS_READLINKAT,
    SYS_FCHMODAT,
    SYS_FACCESSAT,
    SYS_PSELECT6,
    SYS_PPOLL,
    SYS_UNSHARE,
    SYS_SET_ROBUST_LIST,
    SYS_GET_ROBUST_LIST,
    SYS_SPLICE,
    SYS_TEE,
    SYS_SYNC_FILE_RANGE,
    SYS_VMSPLICE,
    SYS_MOVE_PAGES,
    SYS_UTIMENSAT,
    SYS_EPOLL_PWAIT,
    SYS_SIGNALFD,
    SYS_TIMERFD_CREATE,
    SYS_EVENTFD,
    SYS_FALLOCATE,
    SYS_TIMERFD_SETTIME,
    SYS_TIMERFD_GETTIME,
    SYS_ACCEPT4,
    SYS_SIGNALFD4,
    SYS_EVENTFD2,
    SYS_EPOLL_CREATE1,
    SYS_DUP3,
    SYS_PIPE2,
    SYS_IONOTIFY_INIT1,
    SYS_PREADV,
    SYS_PWRITEV,
    SYS_RT_TGSIGQUEUEINFO,
    SYS_PERF_EVENT_OPEN,
    SYS_RECVMMSG,
    SYS_FANOTIFY_INIT,
    SYS_FANOTIFY_MARK,
    SYS_PRLIMIT64,
    SYS_NAME_TO_HANDLE_AT,
    SYS_OPEN_BY_HANDLE_AT,
    SYS_CLOCK_ADJTIME,
    SYS_SYNCFS,
    SYS_SENDMMSG,
    SYS_SETNS,
    SYS_GETCPU,
    SYS_PROCESS_VM_READV,
    SYS_PROCESS_VM_WRITEV,
    SYS_KCMP,
    SYS_FINIT_MODULE,
    SYS_SCHED_SETATTR,
    SYS_SCHED_GETATTR,
    SYS_RENAMEAT2,
    SYS_SECCOMPP,
    SYS_GETRANDOM,
    SYS_MEMFD_CREATE,
    SYS_KEXEC_FILE_LOAD,
    SYS_BPF,
    SYS_EXECVEAT,
    SYS_USERFAULTFD,
    SYS_MEMBARRIER,
    SYS_MLOCK2,
    SYS_COPY_FILE_RANGE,
    SYS_PREADV2,
    SYS_PWRITEV2,
    SYS_PKEY_MPROTECT,
    SYS_PKEY_ALLOC,
    SYS_PKRY_FREE,
    SYS_STATX,
    SYS_IO_PGETEVENTS,
    SYS_RSEQ,
    RESERVED335,
    RESERVED336,
    RESERVED337,
    RESERVED338,
    RESERVED339,
    RESERVED340,
    RESERVED341,
    RESERVED342,
    RESERVED343,
    RESERVED344,
    RESERVED345,
    RESERVED346,
    RESERVED347,
    RESERVED348,
    RESERVED349,
    RAW_SYSCALLS,
    DO_EXIT,
    CAP_CAPABLE,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    VFS_WRITE,
    MEM_PROT_ALERT,
};

/*=============================== INTERNAL STRUCTS ===========================*/

struct context_t {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    enum event_id eventid;
    u8 argc;
    s64 retval;
};


struct args_t {
    unsigned long args[6];
};


struct buf_t {
    u8 buf[MAX_PERCPU_BUFSIZE];
};

/*=============================== KERNEL STRUCTS ===========================*/

struct ipc_namespace {
	struct ns_common ns;
};

struct net {
	struct ns_common ns;
};

struct mnt_namespace {
	struct ns_common ns;
};

struct new_utsname {
	char nodename[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct ns_common ns;
};

struct cgroup_namespace {
	struct ns_common ns;
};

struct cgroup {
	struct kernfs_node *kn;
};

typedef unsigned short __kernel_sa_family_t;

struct sockaddr_un {
	__kernel_sa_family_t sun_family;
	char sun_path[108];
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};


/*=================================== MAPS =====================================*/

BPF_HASH(config_map, u32, u32);                     // Various configurations
BPF_HASH(chosen_events_map, u32, u32);              // Various configurations
BPF_HASH(containers_map, u32, u32);                       // Save container pid namespaces
BPF_HASH(args_map, u64, struct args_t);                    // Persist args info between function entry and return
BPF_PERCPU_ARRAY(bufs, struct buf_t, MAX_BUFFERS);         // Percpu global buffer variables
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);       // Holds offsets to bufs respectively

/*================================== EVENTS ====================================*/

BPF_PERF_OUTPUT(events);                            // Events submission


/*================================== INTERN FUNCTIONS ====================================*/
static __always_inline u32 get_mnt_ns_id(struct nsproxy *ns)
{
    struct mnt_namespace* mntns = READ_KERN(ns->mnt_ns);
    return READ_KERN(mntns->ns.inum);
}

static __always_inline u32 get_pid_ns_id(struct nsproxy *ns)
{
    struct pid_namespace* pidns = READ_KERN(ns->pid_ns_for_children);
    return READ_KERN(pidns->ns.inum);
}

static __always_inline u32 get_uts_ns_id(struct nsproxy *ns)
{
    struct uts_namespace* uts_ns = READ_KERN(ns->uts_ns);
    return READ_KERN(uts_ns->ns.inum);
}

static __always_inline u32 get_ipc_ns_id(struct nsproxy *ns)
{
    struct ipc_namespace* ipc_ns = READ_KERN(ns->ipc_ns);
    return READ_KERN(ipc_ns->ns.inum);
}

static __always_inline u32 get_net_ns_id(struct nsproxy *ns)
{
    struct net* net_ns = READ_KERN(ns->net_ns);
    return READ_KERN(net_ns ->ns.inum);
}

static __always_inline u32 get_cgroup_ns_id(struct nsproxy *ns)
{
    struct cgroup_namespace* cgroup_ns = READ_KERN(ns->cgroup_ns);
    return READ_KERN(cgroup_ns->ns.inum);
}

static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return get_mnt_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return get_pid_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_uts_ns_id(struct task_struct *task)
{
    return get_uts_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ipc_ns_id(struct task_struct *task)
{
    return get_ipc_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_net_ns_id(struct task_struct *task)
{
    return get_net_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_cgroup_ns_id(struct task_struct *task)
{
    return get_cgroup_ns_id(READ_KERN(task->nsproxy));
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18
    nr = READ_KERN(READ_KERN(task->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(task->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
#endif
    return nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    int nr = 0;
    struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);
    struct task_struct *group_leader = READ_KERN(task->group_leader);


#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0))
    // kernel 4.14-4.18
    nr = READ_KERN(READ_KERN(group_leader->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(group_leader->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
#endif
    return nr;
}

static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    int nr = 0;
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct nsproxy *namespaceproxy = READ_KERN(real_parent->nsproxy);
    struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
    unsigned int level = READ_KERN(pid_ns_children->level);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(RHEL_RELEASE_GT_8_0)) && !defined(CORE)
    // kernel 4.14-4.18
    nr = (READ_KERN(real_parent->pids[PIDTYPE_PID].pid)->numbers[level].nr);
#else
    // kernel 4.19 onwards
    struct pid *tpid = READ_KERN(real_parent->thread_pid);
    nr = READ_KERN(tpid->numbers[level].nr);
#endif
    return nr;
}

static __always_inline const u64 get_cgroup_id(struct cgroup *cgrp)
{
    struct kernfs_node *kn = READ_KERN(cgrp->kn);

    if (kn == NULL)
        return 0;

    u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both situations
    bpf_probe_read(&id, sizeof(u64), &kn->id);

    return id;
}

static __always_inline char * get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}


static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = READ_KERN(task->real_parent);
    return READ_KERN(parent->pid);
}


static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int event_chosen(u32 key)
{
    u32 *config = chosen_events_map.lookup(&key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline void get_syscall_args(struct pt_regs *ctx, struct args_t *args)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    args->args[0] = PT_REGS_PARM1(ctx);
    args->args[1] = PT_REGS_PARM2(ctx);
    args->args[2] = PT_REGS_PARM3(ctx);
    args->args[3] = PT_REGS_PARM4(ctx);
    args->args[4] = PT_REGS_PARM5(ctx);
    args->args[5] = PT_REGS_PARM6(ctx);
#else
    struct pt_regs * ctx2 = (struct pt_regs *)ctx->di;
    bpf_probe_read(&args->args[0], sizeof(args->args[0]), &ctx2->di);
    bpf_probe_read(&args->args[1], sizeof(args->args[1]), &ctx2->si);
    bpf_probe_read(&args->args[2], sizeof(args->args[2]), &ctx2->dx);
    bpf_probe_read(&args->args[3], sizeof(args->args[3]), &ctx2->r10);
    bpf_probe_read(&args->args[4], sizeof(args->args[4]), &ctx2->r8);
    bpf_probe_read(&args->args[5], sizeof(args->args[5]), &ctx2->r9);
#endif
}


static __always_inline u32 lookup_pid_ns(struct task_struct *task)
{
    u32 task_pid_ns = get_task_pid_ns_id(task);

    u32 *pid_ns = containers_map.lookup(&task_pid_ns);
    if (pid_ns == 0)
        return 0;

    return *pid_ns;
}

static __always_inline u32 add_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    if (containers_map.lookup(&pid) == 0)
        containers_map.update(&pid, &pid);

    return pid;
}

static __always_inline u32 add_container_pid_ns()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (containers_map.lookup(&pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        containers_map.update(&pid_ns, &pid_ns);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static __always_inline void remove_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    if (containers_map.lookup(&pid) != 0)
        containers_map.delete(&pid);
}

static __always_inline void remove_container_pid_ns()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (containers_map.lookup(&pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            containers_map.delete(&pid_ns);
        }
    }
}

static __always_inline int is_container()
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    return lookup_pid_ns(task);
}


static __always_inline struct buf_t* get_buf(int idx)
{
    return bufs.lookup(&idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bufs_off.update(&buf_idx, &new_off);
}

static __always_inline u32* get_buf_off(int buf_idx)
{
    return bufs_off.lookup(&buf_idx);
}

static __always_inline int save_context_to_buf(struct buf_t *submit_p, void *ptr)
{
    //read the context struct to the beginning of the submit_p
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(struct context_t), ptr);
    //read successfully
    if (rc == 0)
        return sizeof(struct context_t);

    return 0;
}

static __always_inline int save_to_submit_buf(struct buf_t *submit_p, void *ptr, int size, u8 type, u8 tag)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    if (type == 0)
        return 0;

    //get the submit buff offset from BPF_PERCPU_ARRAY: buffs_off
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    //*off & (MAX_PERCPU_BUFSIZE-1) make sure the offset won't beyond the buffer limit
    if (tag != TAG_NONE) {
        rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
        if (rc != 0)
            return 0;

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        set_buf_off(SUBMIT_BUF_IDX, *off);
        return size;
    }

    return 0;
}



static __always_inline int events_perf_submit(struct pt_regs *ctx)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = *off & (MAX_PERCPU_BUFSIZE-1);
    void * data = submit_p->buf;
    return events.perf_submit(ctx, data, size);
}


static __always_inline int save_str_to_buf(struct buf_t *submit_p, void *ptr, u8 tag)
{
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &type);

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE-1)]), 1, &tag);
        if (rc != 0)
            return 0;

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // Satisfy validator for probe read
        return 0;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            return 0;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        set_buf_off(SUBMIT_BUF_IDX, *off);
        return sz + sizeof(int);
    }

    return 0;
}

//buffer overview: number of str elems---str elem---str elem---...
static __always_inline int save_str_arr_to_buf(struct buf_t *submit_p, const char __user *const __user *ptr, u8 tag)
{
    u8 elem_num = 0;

    // mark string array start
    save_to_submit_buf(submit_p, NULL, 0, STR_ARR_T, tag);

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    // Save space for number of elements
    u32 orig_off = *off;
    *off += 1;

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
                // Satisfy validator for probe read
                goto out;
            bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
            *off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int))
            // Satisfy validator for probe read
            goto out;
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        elem_num++;
    }
out:
    set_buf_off(SUBMIT_BUF_IDX, *off);
    // save number of elements in the array
    bpf_probe_read(&(submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &elem_num);
    return 0;
}


static __always_inline int init_context(struct context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char * uts_name = get_task_uts_name(task);
    if (uts_name){
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);
        //context->cgroup_id = bpf_get_current_cgroup_id();
    }
    context->ts = bpf_ktime_get_ns()/1000;
    return 0;
}


static __always_inline int save_args(struct pt_regs *ctx, u32 event_id, bool is_syscall)
{
    u64 id;
    u32 tid;
    struct args_t args = {};

    if (!is_syscall) {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    } else {
        get_syscall_args(ctx, &args);
    }

    id = event_id;
    tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    args_map.update(&id, &args);

    return 0;
}

static __always_inline int load_args(struct args_t *args, bool delete, u32 event_id)
{
    struct args_t *saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = args_map.lookup(&id);
    if (saved_args == 0) {
        // missed entry or not a container
        return -1;
    }

    args->args[0] = saved_args->args[0];
    args->args[1] = saved_args->args[1];
    args->args[2] = saved_args->args[2];
    args->args[3] = saved_args->args[3];
    args->args[4] = saved_args->args[4];
    args->args[5] = saved_args->args[5];

    if (delete)
        args_map.delete(&id);

    return 0;
}

static __always_inline int del_args(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    args_map.delete(&id);

    return 0;
}

#define ENC_ARG_TYPE(n, type) type<<(8*n)
#define ARG_TYPE0(type) ENC_ARG_TYPE(0, type)
#define ARG_TYPE1(type) ENC_ARG_TYPE(1, type)
#define ARG_TYPE2(type) ENC_ARG_TYPE(2, type)
#define ARG_TYPE3(type) ENC_ARG_TYPE(3, type)
#define ARG_TYPE4(type) ENC_ARG_TYPE(4, type)
#define ARG_TYPE5(type) ENC_ARG_TYPE(5, type)
#define DEC_ARG_TYPE(n, enc_type) ((enc_type>>(8*n))&0xFF)

#define ENC_ARG_TAG(n, tag) tag<<(8*n)
#define ARG_TAG0(tag) ENC_ARG_TYPE(0, tag)
#define ARG_TAG1(tag) ENC_ARG_TYPE(1, tag)
#define ARG_TAG2(tag) ENC_ARG_TYPE(2, tag)
#define ARG_TAG3(tag) ENC_ARG_TYPE(3, tag)
#define ARG_TAG4(tag) ENC_ARG_TYPE(4, tag)
#define ARG_TAG5(tag) ENC_ARG_TYPE(5, tag)
#define DEC_ARG_TAG(n, enc_tag) ((enc_tag>>(8*n))&0xFF)

//u64 64bits arg_tag5(8bits)---arg_tag4(8bits)---arg_tag3(8bits)---...---arg_tag0(8bits)
static __always_inline int get_encoded_arg_num(u64 types)
{
    unsigned int i, argc = 0;
    #pragma unroll
    for(i=0; i<6; i++)
    {
        if (DEC_ARG_TYPE(i, types) != NONE_T)
            argc++;
    }
    return argc;
}

static __always_inline int save_args_to_submit_buf(u64 types, u64 tags, struct args_t *args)
{
    unsigned int i;
    short family = 0;

    if (types == 0)
        return 0;

    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    #pragma unroll
    for(i=0; i<6; i++)
    {
        u8 tag = DEC_ARG_TAG(i, tags);
        switch (DEC_ARG_TYPE(i, types))
        {
            case NONE_T:
                break;
            case INT_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(int), INT_T, tag);
                break;
            case UINT_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(unsigned int), UINT_T, tag);
                break;
            case OFF_T_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(off_t), OFF_T_T, tag);
                break;
            case DEV_T_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(dev_t), DEV_T_T, tag);
                break;
            case MODE_T_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(mode_t), MODE_T_T, tag);
                break;
            case LONG_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(long), LONG_T, tag);
                break;
            case ULONG_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(unsigned long), ULONG_T, tag);
                break;
            case SIZE_T_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(size_t), SIZE_T_T, tag);
                break;
            case POINTER_T:
                save_to_submit_buf(submit_p, (void*)&(args->args[i]), sizeof(void*), POINTER_T, tag);
                break;
            case STR_T:
                save_str_to_buf(submit_p, (void *)args->args[i], tag);
                break;
            case SOCKADDR_T:
                if (args->args[i]) {
                    bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                    switch (family)
                    {
                        case AF_UNIX:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_un), SOCKADDR_T, tag);
                            break;
                        case AF_INET:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_in), SOCKADDR_T, tag);
                            break;
                        case AF_INET6:
                            save_to_submit_buf(submit_p, (void*)(args->args[i]), sizeof(struct sockaddr_in6), SOCKADDR_T, tag);
                            break;
                        default:
                            save_to_submit_buf(submit_p, (void*)&family, sizeof(short), SOCKADDR_T, tag);
                    }
                }
                break;
        }
    }

    return 0;
}

static __always_inline int trace_ret_generic(struct pt_regs *ctx, u32 id, u64 types, u64 tags, bool delete_args)
{
    struct context_t context = {};
    struct args_t args = {};

    if (load_args(&args, delete_args, id) != 0)
        return -1;

    if (!is_container())
        return -1;

    if (!event_chosen(id))
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = id;
    context.argc = get_encoded_arg_num(types);
    context.retval = PT_REGS_RC(ctx);
    save_context_to_buf(submit_p, (void*)&context);
    save_args_to_submit_buf(types, tags, &args);

    events_perf_submit(ctx);
    return 0;
}

static __always_inline int trace_ret_generic_fork(struct pt_regs *ctx, u32 id, u64 types, u64 tags)
{
    bool delete_args = true;
    int rc = trace_ret_generic(ctx, id, types, tags, delete_args);
    return 0;
}


#define TRACE_ENT_SYSCALL(name, id)                                     \
int syscall__##name(struct pt_regs *ctx)                                \
{                                                                       \
    if (!is_container())                                                \
        return 0;                                                       \
    return save_args(ctx, id, true);                                    \
}

#define TRACE_ENT_FUNC(name, id)                                        \
int trace_##name(struct pt_regs *ctx)                                   \
{                                                                       \
    if (!is_container())                                                \
        return 0;                                                       \
    return save_args(ctx, id, false);                                   \
}

#define TRACE_RET_FUNC(name, id, types, tags)                           \
int trace_ret_##name(struct pt_regs *ctx)                               \
{                                                                       \
    bool delete_args = true;                                            \
    return trace_ret_generic(ctx, id, types, tags, delete_args);        \
}

#define TRACE_RET_SYSCALL TRACE_RET_FUNC

#define TRACE_RET_FORK_SYSCALL(name, id, types, tags)                   \
int trace_ret_##name(struct pt_regs *ctx)                               \
{                                                                       \
    return trace_ret_generic_fork(ctx, id, types, tags);                \
}


/*============================== SYSCALL HOOKS ==============================*/
TRACE_ENT_SYSCALL(read, SYS_OPEN);
TRACE_RET_SYSCALL(read, SYS_OPEN,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T),
                  ARG_TAG0(TAG_FD)|ARG_TAG1(TAG_DATA));
TRACE_ENT_SYSCALL(open, SYS_OPEN);
TRACE_RET_SYSCALL(open, SYS_OPEN,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_FLAGS));
TRACE_ENT_SYSCALL(openat, SYS_OPENAT);
TRACE_RET_SYSCALL(openat, SYS_OPENAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_FLAGS));
TRACE_ENT_SYSCALL(creat, SYS_CREAT);
TRACE_RET_SYSCALL(creat, SYS_CREAT,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_MODE));
TRACE_ENT_SYSCALL(mmap, SYS_MMAP);
TRACE_RET_SYSCALL(mmap, SYS_MMAP,
                  ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T)|ARG_TYPE4(INT_T)|ARG_TYPE5(OFF_T_T),
                  ARG_TAG0(TAG_ADDR)|ARG_TAG1(TAG_LENGTH)|ARG_TAG2(TAG_PROT)|ARG_TAG3(TAG_FLAGS)|ARG_TAG4(TAG_FD)|ARG_TAG5(TAG_OFFSET));
TRACE_ENT_SYSCALL(mprotect, SYS_MPROTECT);
TRACE_RET_SYSCALL(mprotect, SYS_MPROTECT,
                  ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_ADDR)|ARG_TAG1(TAG_LENGTH)|ARG_TAG2(TAG_PROT));
TRACE_ENT_SYSCALL(pkey_mprotect, SYS_PKEY_MPROTECT);
TRACE_RET_SYSCALL(pkey_mprotect, SYS_PKEY_MPROTECT,
                  ARG_TYPE0(POINTER_T)|ARG_TYPE1(SIZE_T_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T),
                  ARG_TAG0(TAG_ADDR)|ARG_TAG1(TAG_LENGTH)|ARG_TAG2(TAG_PROT)|ARG_TAG3(TAG_PKEY));
TRACE_ENT_SYSCALL(mknod, SYS_MKNOD);
TRACE_RET_SYSCALL(mknod, SYS_MKNOD,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(MODE_T_T)|ARG_TYPE2(DEV_T_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_MODE)|ARG_TAG2(TAG_DEV));
TRACE_ENT_SYSCALL(mknodat, SYS_MKNODAT);
TRACE_RET_SYSCALL(mknodat, SYS_MKNODAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(MODE_T_T)|ARG_TYPE3(DEV_T_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_MODE)|ARG_TAG3(TAG_DEV));
TRACE_ENT_SYSCALL(memfd_create, SYS_MEMFD_CREATE);
TRACE_RET_SYSCALL(memfd_create, SYS_MEMFD_CREATE,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_NAME)|ARG_TAG1(TAG_FLAGS));
TRACE_ENT_SYSCALL(dup, SYS_DUP);
TRACE_RET_SYSCALL(dup, SYS_DUP,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_OLDFD));
TRACE_ENT_SYSCALL(dup2, SYS_DUP2);
TRACE_RET_SYSCALL(dup2, SYS_DUP2,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_OLDFD)|ARG_TAG1(TAG_NEWFD));
TRACE_ENT_SYSCALL(dup3, SYS_DUP3);
TRACE_RET_SYSCALL(dup3, SYS_DUP3,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_OLDFD)|ARG_TAG1(TAG_NEWFD)|ARG_TAG2(TAG_FLAGS));
TRACE_ENT_SYSCALL(newstat, SYS_STAT);
TRACE_RET_SYSCALL(newstat, SYS_STAT,
                  ARG_TYPE0(STR_T),
                  ARG_TAG0(TAG_PATHNAME));
TRACE_ENT_SYSCALL(newlstat, SYS_LSTAT);
TRACE_RET_SYSCALL(newlstat, SYS_LSTAT,
                  ARG_TYPE0(STR_T),
                  ARG_TAG0(TAG_PATHNAME));
TRACE_ENT_SYSCALL(newfstat, SYS_FSTAT);
TRACE_RET_SYSCALL(newfstat, SYS_FSTAT,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FD));
TRACE_ENT_SYSCALL(socket, SYS_SOCKET);
TRACE_RET_SYSCALL(socket, SYS_SOCKET,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_DOMAIN)|ARG_TAG1(TAG_TYPE)|ARG_TAG2(TAG_PROTOCOL));
TRACE_ENT_SYSCALL(close, SYS_CLOSE);
TRACE_RET_SYSCALL(close, SYS_CLOSE,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FD));
TRACE_ENT_SYSCALL(ioctl, SYS_IOCTL);
TRACE_RET_SYSCALL(ioctl, SYS_IOCTL,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(ULONG_T),
                  ARG_TAG0(TAG_FD)|ARG_TAG1(TAG_REQUEST));
TRACE_ENT_SYSCALL(access, SYS_ACCESS);
TRACE_RET_SYSCALL(access, SYS_ACCESS,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_MODE));
TRACE_ENT_SYSCALL(faccessat, SYS_FACCESSAT);
TRACE_RET_SYSCALL(faccessat, SYS_FACCESSAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T)|ARG_TYPE3(INT_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_MODE)|ARG_TAG3(TAG_FLAGS));
TRACE_ENT_SYSCALL(kill, SYS_KILL);
TRACE_RET_SYSCALL(kill, SYS_KILL,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_PID)|ARG_TAG1(TAG_SIG));
TRACE_ENT_SYSCALL(listen, SYS_LISTEN);
TRACE_RET_SYSCALL(listen, SYS_LISTEN,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_BACKLOG));
TRACE_ENT_SYSCALL(connect, SYS_CONNECT);
TRACE_RET_SYSCALL(connect, SYS_CONNECT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_ADDR));
TRACE_ENT_SYSCALL(accept, SYS_ACCEPT);
TRACE_RET_SYSCALL(accept, SYS_ACCEPT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_ADDR));
TRACE_ENT_SYSCALL(accept4, SYS_ACCEPT4);
TRACE_RET_SYSCALL(accept4, SYS_ACCEPT4,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_ADDR));
TRACE_ENT_SYSCALL(bind, SYS_BIND);
TRACE_RET_SYSCALL(bind, SYS_BIND,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_ADDR));
TRACE_ENT_SYSCALL(getsockname, SYS_GETSOCKNAME);
TRACE_RET_SYSCALL(getsockname, SYS_GETSOCKNAME,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(SOCKADDR_T),
                  ARG_TAG0(TAG_SOCKFD)|ARG_TAG1(TAG_ADDR));
TRACE_ENT_SYSCALL(prctl, SYS_PRCTL);
TRACE_RET_SYSCALL(prctl, SYS_PRCTL,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(ULONG_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(ULONG_T)|ARG_TYPE4(ULONG_T),
                  ARG_TAG0(TAG_OPTION)|ARG_TAG1(TAG_ARG2)|ARG_TAG2(TAG_ARG3)|ARG_TAG3(TAG_ARG4)|ARG_TAG4(TAG_ARG5));
TRACE_ENT_SYSCALL(ptrace, SYS_PTRACE);
TRACE_RET_SYSCALL(ptrace, SYS_PTRACE,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(POINTER_T)|ARG_TYPE3(POINTER_T),
                  ARG_TAG0(TAG_REQUEST)|ARG_TAG1(TAG_PID)|ARG_TAG2(TAG_ADDR)|ARG_TAG3(TAG_DATA));
TRACE_ENT_SYSCALL(process_vm_writev, SYS_PROCESS_VM_WRITEV);
TRACE_RET_SYSCALL(process_vm_writev, SYS_PROCESS_VM_WRITEV,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(ULONG_T)|ARG_TYPE5(ULONG_T),
                  ARG_TAG0(TAG_PID)|ARG_TAG1(TAG_LOCAL_IOV)|ARG_TAG2(TAG_LIOVCNT)|ARG_TAG3(TAG_REMOTE_IOV)|ARG_TAG4(TAG_RIOVCNT)|ARG_TAG5(TAG_FLAGS));
TRACE_ENT_SYSCALL(process_vm_readv, SYS_PROCESS_VM_READV);
TRACE_RET_SYSCALL(process_vm_readv, SYS_PROCESS_VM_READV,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(POINTER_T)|ARG_TYPE2(ULONG_T)|ARG_TYPE3(POINTER_T)|ARG_TYPE4(ULONG_T)|ARG_TYPE5(ULONG_T),
                  ARG_TAG0(TAG_PID)|ARG_TAG1(TAG_LOCAL_IOV)|ARG_TAG2(TAG_LIOVCNT)|ARG_TAG3(TAG_REMOTE_IOV)|ARG_TAG4(TAG_RIOVCNT)|ARG_TAG5(TAG_FLAGS));
TRACE_ENT_SYSCALL(init_module, SYS_INIT_MODULE);
TRACE_RET_SYSCALL(init_module, SYS_INIT_MODULE,
                  ARG_TYPE0(POINTER_T)|ARG_TYPE1(ULONG_T)|ARG_TYPE2(STR_T),
                  ARG_TAG0(TAG_MODULE_IMAGE)|ARG_TAG1(TAG_LEN)|ARG_TAG2(TAG_PARAM_VALUES));
TRACE_ENT_SYSCALL(finit_module, SYS_FINIT_MODULE);
TRACE_RET_SYSCALL(finit_module, SYS_FINIT_MODULE,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_FD)|ARG_TAG1(TAG_PARAM_VALUES)|ARG_TAG2(TAG_FLAGS));
TRACE_ENT_SYSCALL(delete_module, SYS_DELETE_MODULE);
TRACE_RET_SYSCALL(delete_module, SYS_DELETE_MODULE,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_NAME)|ARG_TAG1(TAG_FLAGS));
TRACE_ENT_SYSCALL(symlink, SYS_SYMLINK);
TRACE_RET_SYSCALL(symlink, SYS_SYMLINK,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(STR_T),
                  ARG_TAG0(TAG_TARGET)|ARG_TAG1(TAG_LINKPATH));
TRACE_ENT_SYSCALL(symlinkat, SYS_SYMLINKAT);
TRACE_RET_SYSCALL(symlinkat, SYS_SYMLINKAT,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(STR_T),
                  ARG_TAG0(TAG_TARGET)|ARG_TAG1(TAG_NEWDIRFD)|ARG_TAG2(TAG_LINKPATH));
TRACE_ENT_SYSCALL(getdents, SYS_GETDENTS);
TRACE_RET_SYSCALL(getdents, SYS_GETDENTS,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FD));
TRACE_ENT_SYSCALL(getdents64, SYS_GETDENTS64);
TRACE_RET_SYSCALL(getdents64, SYS_GETDENTS64,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FD));
TRACE_ENT_SYSCALL(mount, SYS_MOUNT);
TRACE_RET_SYSCALL(mount, SYS_MOUNT,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(STR_T)|ARG_TYPE3(ULONG_T),
                  ARG_TAG0(TAG_SOURCE)|ARG_TAG1(TAG_TARGET)|ARG_TAG2(TAG_FILESYSTEMTYPE)|ARG_TAG3(TAG_MOUNTFLAGS));
TRACE_ENT_SYSCALL(umount, SYS_UMOUNT);
TRACE_RET_SYSCALL(umount, SYS_UMOUNT,
                  ARG_TYPE0(STR_T),
                  ARG_TAG0(TAG_TARGET));
TRACE_ENT_SYSCALL(unlink, SYS_UNLINK);
TRACE_RET_SYSCALL(unlink, SYS_UNLINK,
                  ARG_TYPE0(STR_T),
                  ARG_TAG0(TAG_PATHNAME));
TRACE_ENT_SYSCALL(unlinkat, SYS_UNLINKAT);
TRACE_RET_SYSCALL(unlinkat, SYS_UNLINKAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_FLAGS));
TRACE_ENT_SYSCALL(setuid, SYS_SETUID);
TRACE_RET_SYSCALL(setuid, SYS_SETUID,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_UID));
TRACE_ENT_SYSCALL(setgid, SYS_SETGID);
TRACE_RET_SYSCALL(setgid, SYS_SETGID,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_GID));
TRACE_ENT_SYSCALL(setfsuid, SYS_SETFSUID);
TRACE_RET_SYSCALL(setfsuid, SYS_SETFSUID,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FSUID));
TRACE_ENT_SYSCALL(setfsgid, SYS_SETFSGID);
TRACE_RET_SYSCALL(setfsgid, SYS_SETFSGID,
                  ARG_TYPE0(INT_T),
                  ARG_TAG0(TAG_FSGID));
TRACE_ENT_SYSCALL(setreuid, SYS_SETREUID);
TRACE_RET_SYSCALL(setreuid, SYS_SETREUID,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_RUID)|ARG_TAG1(TAG_EUID));
TRACE_ENT_SYSCALL(setregid, SYS_SETREGID);
TRACE_RET_SYSCALL(setregid, SYS_SETREGID,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T),
                  ARG_TAG0(TAG_RGID)|ARG_TAG1(TAG_EGID));
TRACE_ENT_SYSCALL(setresuid, SYS_SETRESUID);
TRACE_RET_SYSCALL(setresuid, SYS_SETRESUID,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_RUID)|ARG_TAG1(TAG_EUID)|ARG_TAG2(TAG_SUID));
TRACE_ENT_SYSCALL(setresgid, SYS_SETRESGID);
TRACE_RET_SYSCALL(setresgid, SYS_SETRESGID,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(INT_T)|ARG_TYPE2(INT_T),
                  ARG_TAG0(TAG_RGID)|ARG_TAG1(TAG_EGID)|ARG_TAG2(TAG_SGID));
TRACE_ENT_SYSCALL(chown, SYS_CHOWN);
TRACE_RET_SYSCALL(chown, SYS_CHOWN,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_OWNER)|ARG_TAG2(TAG_GROUP));
TRACE_ENT_SYSCALL(fchown, SYS_FCHOWN);
TRACE_RET_SYSCALL(fchown, SYS_FCHOWN,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T),
                  ARG_TAG0(TAG_FD)|ARG_TAG1(TAG_OWNER)|ARG_TAG2(TAG_GROUP));
TRACE_ENT_SYSCALL(lchown, SYS_LCHOWN);
TRACE_RET_SYSCALL(lchown, SYS_LCHOWN,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(UINT_T)|ARG_TYPE2(UINT_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_OWNER)|ARG_TAG2(TAG_GROUP));
TRACE_ENT_SYSCALL(fchownat, SYS_FCHOWNAT);
TRACE_RET_SYSCALL(fchownat, SYS_FCHOWNAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(UINT_T)|ARG_TYPE3(UINT_T)|ARG_TYPE4(INT_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_OWNER)|ARG_TAG3(TAG_GROUP)|ARG_TAG4(TAG_FLAGS));
TRACE_ENT_SYSCALL(chmod, SYS_CHMOD);
TRACE_RET_SYSCALL(chmod, SYS_CHMOD,
                  ARG_TYPE0(STR_T)|ARG_TYPE1(MODE_T_T),
                  ARG_TAG0(TAG_PATHNAME)|ARG_TAG1(TAG_MODE));
TRACE_ENT_SYSCALL(fchmod, SYS_FCHMOD);
TRACE_RET_SYSCALL(fchmod, SYS_FCHMOD,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(MODE_T_T),
                  ARG_TAG0(TAG_FD)|ARG_TAG1(TAG_MODE));
TRACE_ENT_SYSCALL(fchmodat, SYS_FCHMODAT);
TRACE_RET_SYSCALL(fchmodat, SYS_FCHMODAT,
                  ARG_TYPE0(INT_T)|ARG_TYPE1(STR_T)|ARG_TYPE2(MODE_T_T)|ARG_TYPE3(INT_T),
                  ARG_TAG0(TAG_DIRFD)|ARG_TAG1(TAG_PATHNAME)|ARG_TAG2(TAG_MODE)|ARG_TAG3(TAG_FLAGS));
TRACE_ENT_SYSCALL(fork, SYS_FORK);
TRACE_RET_FORK_SYSCALL(fork, SYS_FORK, 0, 0);
TRACE_ENT_SYSCALL(vfork, SYS_VFORK);
TRACE_RET_FORK_SYSCALL(vfork, SYS_VFORK, 0, 0);
TRACE_ENT_SYSCALL(clone, SYS_CLONE);
TRACE_RET_FORK_SYSCALL(clone, SYS_CLONE, ARG_TYPE0(ULONG_T), ARG_TAG0(TAG_FLAGS));

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct context_t context = {};

    if (!is_container())
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = RAW_SYSCALLS;
    context.argc = 1;
    context.retval = 0;

    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&(args->id), sizeof(int), INT_T, TAG_SYSCALL);
    events_perf_submit((struct pt_regs *)args);
    
    return 0;
}


int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct context_t context = {};

    //add_container_pid_ns();
    add_pid();

    if (!is_container())
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    //int show_env = get_config(CONFIG_EXEC_ENV);

    context.eventid = SYS_EXECVE;
    // if (show_env)
    //     context.argc = 3;
    // else
    context.argc = 2;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_context_to_buf(submit_p, (void*)&context);

    save_str_to_buf(submit_p, (void *)filename, TAG_PATHNAME);
    save_str_arr_to_buf(submit_p, (void *)__argv, TAG_ARGV);
    // if (show_env)
    //     save_str_arr_to_buf(submit_p, (void *)__envp, TAG_ENVP);

    events_perf_submit(ctx);
    return 0;
}



int trace_ret_execve(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    struct context_t context = {};

    if (!is_container())
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVE;
    context.argc = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

int syscall__execveat(struct pt_regs *ctx,
    const int dirfd,
    const char __user *pathname,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp,
    const int flags)
{
    struct context_t context = {};

    //add_container_pid_ns();
    add_pid();

    if (!is_container())
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    //int show_env = get_config(CONFIG_EXEC_ENV);

    context.eventid = SYS_EXECVEAT;
    // if (show_env)
    //     context.argc = 5;
    // else
    context.argc = 4;
    context.retval = 0;     // assume execve succeeded. if not, a ret event will be sent too
    save_context_to_buf(submit_p, (void*)&context);

    save_to_submit_buf(submit_p, (void*)&dirfd, sizeof(int), INT_T, TAG_DIRFD);
    save_str_to_buf(submit_p, (void *)pathname, TAG_PATHNAME);
    save_str_arr_to_buf(submit_p, (void *)__argv, TAG_ARGV);
    // if (show_env)
    //     save_str_arr_to_buf(submit_p, __envp, TAG_ENVP);
    save_to_submit_buf(submit_p, (void*)&flags, sizeof(int), INT_T, TAG_FLAGS);

    events_perf_submit(ctx);
    return 0;
}

int trace_ret_execveat(struct pt_regs *ctx)
{
    // we can't load string args here as after execve memory is wiped
    struct context_t context = {};

    if (!is_container())
        return 0;

    init_context(&context);
    set_buf_off(SUBMIT_BUF_IDX, sizeof(struct context_t));
    struct buf_t *submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

    context.eventid = SYS_EXECVEAT;
    context.argc = 0;
    context.retval = PT_REGS_RC(ctx);

    if (context.retval == 0)
        return 0;   // we are only interested in failed execs

    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}

/*============================== OTHER HOOKS ==============================*/
