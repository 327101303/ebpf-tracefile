#include "ctrace.bpf.h"



/*============================ HELPER FUNCTIONS ==============================*/

static __always_inline int event_chosen(u32 key) {
    u32* config = bpf_map_lookup_elem(&chosen_events_map, &key);
    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int get_config(u32 key) {

    u32* config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

static __always_inline int equality_filter_matches(int filter_config, void* filter_map, void* key) {
    int config = get_config(filter_config);
    if (!config)
        return 1;

    u32* equality = bpf_map_lookup_elem(filter_map, key);
    if (equality != NULL) {
        return *equality;
    }

    if (config == FILTER_IN)
        return 0;

    return 1;
}

static __always_inline int init_context(context_t* context) {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char* uts_name = get_task_uts_name(task);
    if (uts_name) {
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);
    }

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns() / 1000;

    // Clean Stack Trace ID
    context->argc = 0;

    return 0;
}

static __always_inline buf_t* get_buf(int idx) {
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off) {
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32* get_buf_off(int buf_idx) {
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// TODO save_to_buf
static __always_inline int save_to_buf(buf_t* submit_p, void* ptr, u32 size, u8 type, u8 tag) {
    // The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
    if (type == 0)
        return 0;

    if (size == 0)
        return 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument type
    int rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
        // Satisfy validator for probe read
        return 0;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }
    *off += 1;

    if (*off > MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    rc = bpf_probe_read(&(submit_p->buf[*off]), size, ptr);
    if (rc == 0) {
        *off += size;
        return 1;
    }

    *off -= 2;
    return 0;
}

/*
static __always_inline int save_to_buf(buf_t* submit_p, void* ptr, int size, u8 type, u8 tag) {
    // The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

    // Data saved to submit buf: [type][tag][*ptr]
    if (type == 0)
        return 0;

    if (size == 0)
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
    // *off & (MAX_PERCPU_BUFSIZE-1) make sure the offset won't beyond the buffer limit
    if (tag != TAG_NONE) {
        rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &tag);
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
*/

// Context will always be at the start of the submission buffer
// It may be needed to resave the context if the arguments number changed by logic
static __always_inline int save_context_to_buf(buf_t* submit_p, void* ptr) {
    //read the context struct to the beginning of the submit_p
    int rc = bpf_probe_read(&(submit_p->buf[0]), sizeof(context_t), ptr);
    //read successfully
    if (rc == 0)
        return sizeof(context_t);

    return 0;
}

static __always_inline context_t init_and_save_context(void* ctx, buf_t* submit_p, u32 id, u8 argnum, long ret) {
    context_t context = {};
    init_context(&context);
    context.eventid = id;
    context.argc = argnum;
    context.retval = ret;

    save_context_to_buf(submit_p, (void*)&context);
    return context;
}

// TODO save_str_to_buf
static __always_inline int save_str_to_buf(buf_t* submit_p, void* ptr, u8 tag) {
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;
    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        return 0;

    // Save argument type
    u8 type = STR_T;
    bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &type);

    *off += 1;

    // Save argument tag
    if (tag != TAG_NONE) {
        int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &tag);
        if (rc != 0) {
            *off -= 1;
            return 0;
        }

        *off += 1;
    }

    if (*off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) {
        // Satisfy validator for probe read
        *off -= 2;
        return 0;
    }

    // Read into buffer
    int sz = bpf_probe_read_str(&(submit_p->buf[*off + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        if (*off > MAX_PERCPU_BUFSIZE - sizeof(int)) {
            // Satisfy validator for probe read
            *off -= 2;
            return 0;
        }
        bpf_probe_read(&(submit_p->buf[*off]), sizeof(int), &sz);
        *off += sz + sizeof(int);
        return 1;
    }

    *off -= 2;
    return 0;
}

static __always_inline int save_str_arr_to_buf(buf_t* submit_p, const char __user* const __user* ptr, u8 tag) {
    // Data saved to submit buf: [type][tag][str count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;

    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return 0;

    // mark string array start
    u8 type = STR_ARR_T;
    int rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &type);
    if (rc != 0)
        return 0;

    *off += 1;

    // Save argument tag
    rc = bpf_probe_read(&(submit_p->buf[*off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &tag);
    if (rc != 0) {
        *off -= 1;
        return 0;
    }

    *off += 1;

    // Save space for number of elements
    u32 orig_off = *off;
    *off += 1;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char* argp = NULL;
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
        }
        else {
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
    // save number of elements in the array
    bpf_probe_read(&(submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &elem_num);
    return 1;
}

#define DEC_ARG(n, enc_arg) ((enc_arg>>(8*n))&0xFF)

//u64 64bits arg_tag5(8bits)---arg_tag4(8bits)---arg_tag3(8bits)---...---arg_tag0(8bits)
static __always_inline int get_encoded_arg_num(u64 types) {
    unsigned int i, argc = 0;
#pragma unroll
    for (i = 0; i < 6; i++) {
        if (DEC_ARG(i, types) != NONE_T)
            argc++;
    }
    return argc;
}

static __always_inline int save_args_to_buf(u64 types, u64 tags, struct args_t* args) {
    unsigned int i;
    unsigned int rc = 0;
    unsigned int argc = 0;
    short family = 0;

    if (types == 0)
        return 0;

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;

#pragma unroll
    for (i = 0; i < 6; i++) {
        int size = 0;
        u8 type = DEC_ARG(i, types);
        u8 tag = DEC_ARG(i, tags);
        switch (type) {
        case NONE_T:
            break;
        case INT_T:
            size = sizeof(int);
            break;
        case UINT_T:
            size = sizeof(unsigned int);
            break;
        case OFF_T_T:
            size = sizeof(off_t);
            break;
        case DEV_T_T:
            size = sizeof(dev_t);
            break;
        case MODE_T_T:
            size = sizeof(mode_t);
            break;
        case LONG_T:
            size = sizeof(long);
            break;
        case ULONG_T:
            size = sizeof(unsigned long);
            break;
        case SIZE_T_T:
            size = sizeof(size_t);
            break;
        case POINTER_T:
            size = sizeof(void*);
            break;
        case STR_T:
            rc = save_str_to_buf(submit_p, (void*)args->args[i], tag);
            break;
        case SOCKADDR_T:
            if (args->args[i]) {
                bpf_probe_read(&family, sizeof(short), (void*)args->args[i]);
                switch (family) {
                case AF_UNIX:
                    size = sizeof(struct sockaddr_un);
                    break;
                case AF_INET:
                    size = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6:
                    size = sizeof(struct sockaddr_in6);
                    break;
                default:
                    size = sizeof(short);
                }
                rc = save_to_buf(submit_p, (void*)(args->args[i]), size, type, tag);
            }
            else {
                rc = save_to_buf(submit_p, &family, sizeof(short), type, tag);
            }
            break;
        }
        if ((type != NONE_T) && (type != STR_T) && (type != SOCKADDR_T))
            rc = save_to_buf(submit_p, (void*)&(args->args[i]), size, type, tag);

        if (rc > 0) {
            argc++;
            rc = 0;
        }
    }

    return argc;
}

static __always_inline int events_perf_submit(void* ctx) {
    u32* off = get_buf_off(SUBMIT_BUF_IDX);
    if (off == NULL)
        return -1;
    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return -1;

    /* satisfy validator by setting buffer bounds */
    int size = *off & (MAX_PERCPU_BUFSIZE - 1);
    void* data = submit_p->buf;
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);
}

static __always_inline int save_args(struct args_t* args, u32 event_id) {
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&args_map, &id, args, BPF_ANY);

    return 0;
}

static __always_inline int save_args_from_regs(struct pt_regs* ctx, u32 event_id, bool is_syscall) {
    args_t args = {};

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (is_x86_compat(task) && is_syscall) {
#if defined(bpf_target_x86)
        // bpf_probe_read(args.args, sizeof(6 * sizeof(u64)), (void*)ctx->args);
        args.args[0] = ctx->bx;
        args.args[1] = ctx->cx;
        args.args[2] = ctx->dx;
        args.args[3] = ctx->si;
        args.args[4] = ctx->di;
        args.args[5] = ctx->bp;
#endif
    }
    else {
        args.args[0] = PT_REGS_PARM1(ctx);
        args.args[1] = PT_REGS_PARM2(ctx);
        args.args[2] = PT_REGS_PARM3(ctx);
        args.args[3] = PT_REGS_PARM4(ctx);
        args.args[4] = PT_REGS_PARM5(ctx);
        args.args[5] = PT_REGS_PARM6(ctx);
    }

    return save_args(&args, event_id);
}

static __always_inline int load_args(struct args_t* args, bool delete, u32 event_id) {
    struct args_t* saved_args;
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    saved_args = bpf_map_lookup_elem(&args_map, &id);
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
        bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline int del_args(u32 event_id) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;

    bpf_map_delete_elem(&args_map, &id);

    return 0;
}

static __always_inline u32 add_pid() {
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&containers_map, &pid)) {
        bpf_map_update_elem(&containers_map, &pid, &pid, BPF_ANY);
    }

    return pid;
}

static __always_inline u32 add_container_pid_ns() {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (bpf_map_lookup_elem(&containers_map, &pid_ns) != 0)
        // Container pidns was already added to map
        return pid_ns;

    // If pid equals 1 - start tracing the container
    if (get_task_ns_pid(task) == 1) {
        // A new container/pod was started - add pid namespace to map
        bpf_map_update_elem(&containers_map, &pid_ns, &pid_ns, BPF_ANY);
        return pid_ns;
    }

    // Not a container/pod
    return 0;
}

static __always_inline void remove_pid() {
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&containers_map, &pid)) {
        bpf_map_delete_elem(&containers_map, &pid);
    }
}

static __always_inline void remove_container_pid_ns() {
    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();

    u32 pid_ns = get_task_pid_ns_id(task);
    if (bpf_map_lookup_elem(&containers_map, &pid_ns) != 0) {
        // If pid equals 1 - stop tracing this pid namespace
        if (get_task_ns_pid(task) == 1) {
            bpf_map_delete_elem(&containers_map, &pid_ns);
        }
    }
}

static __always_inline int should_trace() {
    // struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    // u32 host_pid = bpf_get_current_pid_tgid() >> 32;

    context_t context = {};
    init_context(&context);

    // 不跟踪自己
    if (get_config(CONFIG_TRACEE_PID) == context.host_pid) {
        return 0;
    }

    // if (get_config(CONFIG_FILTER_UID) > 0) {
    //     if (!uid_filter_matches()) {
    //         return 0;
    //     }
    // }

    if (!equality_filter_matches(CONFIG_COMM_FILTER, &comm_filter, &context.comm)) {
        return 0;
    }

    return 1;
}

static __always_inline int trace_ret_generic(void* ctx, u32 id, u64 types, u64 tags, struct args_t* args, long ret) {
    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    bpf_printk("trace_ret_generic, got submit_p");
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    u8 argnum = save_args_to_buf(types, tags, args);
    bpf_printk("trace_ret_generic, saved types and tags");
    context_t context = {};
    init_context(&context);
    context.argc = argnum;
    context.retval = ret;
    context.eventid = id;
    save_context_to_buf(submit_p, (void*)&context);
    bpf_printk("trace_ret_generic, saved context, argc=%d", context.argc);
    events_perf_submit(ctx);
    bpf_printk("trace_ret_generic, submitted context");
    return 0;
}



/*============================== SYSCALL HOOKS ===============================*/

/** struct bpf_raw_tracepoint_args *ctx; args[0] is struct pt_regs *regs and
 * args[1] is long id. struct pt_regs is a copy of the CPU registers at the
 * time sys_enter was called. id is the ID of the syscall.
 **/
 // TODO sys_enter
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args* ctx) {

    struct args_t args_tmp = {};
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    int id = ctx->args[1];
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
    struct pt_regs* regs = (struct pt_regs*)ctx->args[0];

    if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
        args_tmp.args[0] = READ_KERN(regs->bx);
        args_tmp.args[1] = READ_KERN(regs->cx);
        args_tmp.args[2] = READ_KERN(regs->dx);
        args_tmp.args[3] = READ_KERN(regs->si);
        args_tmp.args[4] = READ_KERN(regs->di);
        args_tmp.args[5] = READ_KERN(regs->bp);
#endif // bpf_target_x86
    }
    else {
        args_tmp.args[0] = READ_KERN(PT_REGS_PARM1(regs));
        args_tmp.args[1] = READ_KERN(PT_REGS_PARM2(regs));
        args_tmp.args[2] = READ_KERN(PT_REGS_PARM3(regs));
#if defined(bpf_target_x86)
        // x86-64: r10 used instead of rcx (4th param to a syscall)
        args_tmp.args[3] = READ_KERN(regs->r10);
#else
        args_tmp.args[3] = READ_KERN(PT_REGS_PARM4(regs));
#endif
        args_tmp.args[4] = READ_KERN(PT_REGS_PARM5(regs));
        args_tmp.args[5] = READ_KERN(PT_REGS_PARM6(regs));
    }
#else  // CONFIG_ARCH_HAS_SYSCALL_WRAPPER
    bpf_probe_read(args_tmp.args, sizeof(6 * sizeof(u64)), (void*)ctx->args);
    // args_tmp.args[0] = ctx->args[0];
    // args_tmp.args[1] = ctx->args[1];
    // args_tmp.args[2] = ctx->args[2];
    // args_tmp.args[3] = ctx->args[3];
    // args_tmp.args[4] = ctx->args[4];
    // args_tmp.args[5] = ctx->args[5];
#endif // CONFIG_ARCH_HAS_SYSCALL_WRAPPER

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32* id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    u32 pid = bpf_get_current_pid_tgid();

    if (!should_trace()) {
        return 0;
    }

    // execve events may add new pids to the traced pids set
    // if (id == SYS_EXECVE || id == SYS_EXECVEAT) {
    //     //add_container_pid_ns();
    //     // add_pid();
    //     // We passed all filters (in should_trace()) - add this pid to traced pids set
    //     bpf_map_update_elem(&traced_pids_map, &pid, &pid, BPF_ANY);
    //     // bpf_printk("raw_tracepoint_sys_exit add this id: %d to map", id);
    // }

    if (event_chosen(RAW_SYS_ENTER)) {
        buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL) {
            return 0;
        }

        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context_t context = init_and_save_context((void*)ctx, submit_p, RAW_SYS_ENTER, 1 /*argnum*/, 0 /*ret*/);
        // context_t context = {};
        // init_context(&context);
        // context.eventid = RAW_SYS_ENTER;
        // context.argc = 1;
        // context.retval = 0;
        // save_context_to_buf(submit_p, (void*)&context);

        u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }
        save_to_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));

        events_perf_submit(ctx);
    }
    // exit, exit_group and rt_sigreturn syscalls don't return - don't save args for them
    if (id != SYS_EXIT && id != SYS_EXIT_GROUP && id != SYS_RT_SIGRETURN) {
        save_args(&args_tmp, id);
        // save_args_from_regs(&args_tmp, id, true);
    }

    // call syscall handler, if exists
    // enter tail calls should never delete saved args
    // bpf_tail_call(ctx, &sys_enter_tails, id);
    return 0;
}


SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args* ctx) {

    int id;
    long ret;
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    struct pt_regs* regs = (struct pt_regs*)ctx->args[0];
    id = READ_KERN(regs->orig_ax);
    ret = ctx->args[1];
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls so we can send to the correct handler
        u32* id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }

    struct args_t saved_args = {};
    bool delete_args = true;
    if (load_args(&saved_args, delete_args, id) != 0) {
        return 0;
    }

    if (!should_trace())
        return 0;
    // del_args(id);

    // fork events may add new pids to the traced pids set
    // perform this check after should_trace() to only add forked childs of a traced parent
    if (id == SYS_CLONE || id == SYS_FORK || id == SYS_VFORK) {
        //add_container_pid_ns();
        add_pid();
        bpf_printk("raw_tracepoint_sys_exit add this id: %d to map", id);
    }
    if (event_chosen(RAW_SYS_EXIT)) {
        buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
        if (submit_p == NULL)
            return 0;
        set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
        context_t context = {};
        init_context(&context);
        context.eventid = RAW_SYS_EXIT;
        context.argc = 1;
        context.retval = ret;
        save_context_to_buf(submit_p, (void*)&context);

        u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
        if (!tags) {
            return -1;
        }
        save_to_buf(submit_p, (void*)&id, sizeof(int), INT_T, DEC_ARG(0, *tags));
        events_perf_submit(ctx);
    }
    if (event_chosen(id)) {
        u64 types = 0;
        u64 tags = 0;
        bool submit_event = true;
        if (id != SYS_EXECVE && id != SYS_EXECVEAT) {
            u64* saved_types = bpf_map_lookup_elem(&params_types_map, &id);
            u64* saved_tags = bpf_map_lookup_elem(&params_names_map, &id);
            if (!saved_types || !saved_tags) {
                return -1;
            }
            types = *saved_types;
            tags = *saved_tags;
            bpf_printk("raw_tracepoint_sys_exit get params from map for:%d", id);
        }
        else {
            // We can't use saved args after execve syscall, as pointers are invalid
            // To avoid showing execve event both on entry and exit,
            // we only output failed execs
            if (ret == 0)
                submit_event = false;
        }
        if (submit_event) {
            bpf_printk("raw_tracepoint_sys_exit called trace_ret_g for:%d, types: %ld, tags: %ld", id, types, tags);
            trace_ret_generic(ctx, id, types, tags, &saved_args, ret);
        }

    }
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct bpf_raw_tracepoint_args* ctx) {

    // if (!should_trace())
    //     return 0;

    // // if (get_config(CONFIG_MODE) == MODE_CONTAINER_NEW)
    // //     remove_pid_ns_if_needed();
    // // else
    // remove_pid();

    // buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    // if (submit_p == NULL)
    //     return 0;
    // set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    // init_and_save_context(ctx, submit_p, SCHED_PROCESS_EXIT, 0, 0);

    // events_perf_submit(ctx);
    return 0;
}


SEC("raw_tracepoint/sys_execve")
int syscall__execve(void* ctx) {
    struct args_t args = {};
    u8 argc = 0;
    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVE) != 0) {
        return -1;
    }
    if (!event_chosen(SYS_EXECVE)) {
        return 0;
    }
    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL) {
        return 0;
    }
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));
    context_t context = {};
    init_context(&context);
    context.eventid = SYS_EXECVE;
    context.argc = 2;
    context.retval = 0;
    save_context_to_buf(submit_p, (void*)&context);

    u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }
    argc += save_str_to_buf(submit_p, (void*)args.args[0] /*filename*/, DEC_ARG(0, *tags));
    argc += save_str_arr_to_buf(submit_p, (const char* const*)args.args[1] /*argv*/, DEC_ARG(1, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argc += save_str_arr_to_buf(submit_p, (const char* const*)args.args[2] /*envp*/, DEC_ARG(2, *tags));
    }
    context.argc = argc;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}


SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(void* ctx) {
    struct args_t args = {};
    u8 argnum = 0;

    bool delete_args = false;
    if (load_args(&args, delete_args, SYS_EXECVEAT) != 0)
        return -1;

    if (!event_chosen(SYS_EXECVEAT))
        return 0;

    buf_t* submit_p = get_buf(SUBMIT_BUF_IDX);
    if (submit_p == NULL)
        return 0;
    set_buf_off(SUBMIT_BUF_IDX, sizeof(context_t));

    context_t context = {};
    init_context(&context);
    context.eventid = SYS_EXECVEAT;
    context.argc = 4;
    context.retval = 0;
    u64* tags = bpf_map_lookup_elem(&params_names_map, &context.eventid);
    if (!tags) {
        return -1;
    }

    argnum += save_to_buf(submit_p, (void*)&args.args[0] /*dirfd*/, sizeof(int), INT_T, DEC_ARG(0, *tags));
    argnum += save_str_to_buf(submit_p, (void*)args.args[1] /*pathname*/, DEC_ARG(1, *tags));
    argnum += save_str_arr_to_buf(submit_p, (const char* const*)args.args[2] /*argv*/, DEC_ARG(2, *tags));
    if (get_config(CONFIG_EXEC_ENV)) {
        argnum += save_str_arr_to_buf(submit_p, (const char* const*)args.args[3] /*envp*/, DEC_ARG(3, *tags));
    }
    argnum += save_to_buf(submit_p, (void*)&args.args[4] /*flags*/, sizeof(int), INT_T, DEC_ARG(4, *tags));

    context.argc = argnum;
    save_context_to_buf(submit_p, (void*)&context);
    events_perf_submit(ctx);
    return 0;
}



char LICENSE[] SEC("license") = "GPL";