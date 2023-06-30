// #include "http.c"
#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/l7_req.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1

#define METHOD_UNKNOWN      0
#define METHOD_GET          1
#define METHOD_POST         2
#define METHOD_PUT         3
#define METHOD_PATCH        4
#define METHOD_DELETE       5
#define METHOD_HEAD       6
#define METHOD_CONNECT    7
#define METHOD_OPTIONS       8
#define METHOD_TRACE       9


#define MAX_PAYLOAD_SIZE 512
#define PAYLOAD_PREFIX_SIZE 16


char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline
int parse_http_method(char *buf_prefix) {
    if (buf_prefix[0] == 'G' && buf_prefix[1] == 'E' && buf_prefix[2] == 'T') {
            return METHOD_GET;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'O' && buf_prefix[2] == 'S' && buf_prefix[3] == 'T'){
        return METHOD_POST;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'U' && buf_prefix[2] == 'T'){
        return METHOD_PUT;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'A' && buf_prefix[2] == 'T' && buf_prefix[3] == 'C' && buf_prefix[4] == 'H'){
        return METHOD_PATCH;
    }else if(buf_prefix[0] == 'D' && buf_prefix[1] == 'E' && buf_prefix[2] == 'L' && buf_prefix[3] == 'E' && buf_prefix[4] == 'T' && buf_prefix[5] == 'E'){
        return METHOD_DELETE;
    }else if(buf_prefix[0] == 'H' && buf_prefix[1] == 'E' && buf_prefix[2] == 'A' && buf_prefix[3] == 'D'){
        return METHOD_HEAD;
    }else if (buf_prefix[0] == 'C' && buf_prefix[1] == 'O' && buf_prefix[2] == 'N' && buf_prefix[3] == 'N' && buf_prefix[4] == 'E' && buf_prefix[5] == 'C' && buf_prefix[6] == 'T'){
        return METHOD_CONNECT;
    }else if(buf_prefix[0] == 'O' && buf_prefix[1] == 'P' && buf_prefix[2] == 'T' && buf_prefix[3] == 'I' && buf_prefix[4] == 'O' && buf_prefix[5] == 'N' && buf_prefix[6] == 'S'){
        return METHOD_OPTIONS;
    }else if(buf_prefix[0] == 'T' && buf_prefix[1] == 'R' && buf_prefix[2] == 'A' && buf_prefix[3] == 'C' && buf_prefix[4] == 'E'){
        return METHOD_TRACE;
    }
    return -1;
}

struct l7_event {
    __u64 fd;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
};

// Instead of allocating on bpf stack, we allocate on a per-CPU array map
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");


// send l7 events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");


// when given with __type macro below
// type *btf.Pointer not supported
struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");


// After socket creation and connection establishment, the kernel will call the
// write function of the socket's protocol handler to send data to the remote
// peer. The kernel will call the read function of the socket's protocol handler
// to receive data from the remote peer.

// Flow:
// 1. sys_enter_write
    // -- TODO: check if write was successful (return value), sys_exit_write ?
// 2. sys_enter_read
// 3. sys_exit_read


SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_write* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);

    if (!req) {
        char msg[] = "Err: Could not get request from l7_request_heap";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }

    req->protocol = PROTOCOL_UNKNOWN;
    req->write_time_ns = bpf_ktime_get_ns();

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = ctx->fd;

    if(ctx->buf && ctx->count > PAYLOAD_PREFIX_SIZE){
        // read first 16 bytes of write buffer
        char buf_prefix[PAYLOAD_PREFIX_SIZE];
        long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(ctx->buf)) ;
        
        if (r < 0) {
            char msg[] = "could not read into buf_prefix - %ld";
            bpf_trace_printk(msg, sizeof(msg), r);
            return 0;
        }

        int m = parse_http_method(buf_prefix);
        if (m == -1){
            req->protocol = PROTOCOL_UNKNOWN;
            req->method = METHOD_UNKNOWN;
        }else{
            req->protocol = PROTOCOL_HTTP;
            req->method = m;
        }
    }else{
        char msgCtx[] = "write buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        return 0;
    }
    
    // copy request payload
    // we should copy as much as the size of write buffer, 
    // if we copy more, we will get a kernel error ?

    if(ctx->count >= MAX_PAYLOAD_SIZE){
        // will not be able to copy all of it
        bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)ctx->buf);
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    }else{
        // copy only the first ctx->count bytes (all we have)
        bpf_probe_read(&req->payload, ctx->count, (const void *)ctx->buf);
        req->payload_size = ctx->count;
        req->payload_read_complete = 1;
    }
    
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if(res < 0)
    {
		char msg[] = "Error writing to active_l7_requests - %ld";
		bpf_trace_printk(msg, sizeof(msg), res);
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_read* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = ctx->fd;

    // assume process is reading from the same socket it wrote to
    void* active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if(!active_req) // if not found
    {
        return 0;
    }
    
    struct read_args args = {};
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    args.size = ctx->count;

    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if(res < 0)
    {
        char msg[] = "Error writing to active_reads - %ld";
        bpf_trace_printk(msg, sizeof(msg), res);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_read* ctx) {
    if (ctx->ret < 0) { // read failed
        // -ERRNO
        __u64 id = bpf_get_current_pid_tgid();

        // check if this read was initiated by us
        struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
        if (!read_info) {
            return 0;
        }

        struct socket_key k = {};
        k.pid = id >> 32;
        k.fd = read_info->fd;

        // request failed 
        bpf_map_delete_elem(&active_reads, &id);
        bpf_map_delete_elem(&active_l7_requests, &k);

        // print error
        char msg[] = "read failed - %ld";
        bpf_trace_printk(msg, sizeof(msg), ctx->ret);

        // TODO: send error to user space, request failed
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        return 0;
    }
    
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = read_info->fd; 


    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        return 0;
    }

    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }

    e->fd = k.fd;
    e->pid = k.pid;

    e->method = active_req->method;

    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    e->protocol = active_req->protocol;
    e->duration = bpf_ktime_get_ns() - active_req->write_time_ns;
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    

    // TODO: get status from buffer
    // char *buf = args->buf;
    // __u64 size = args->size;   

    // if (e->protocol == PROTOCOL_HTTP) {
    //     e->status = parse_http_status(buf);
    // } 
       
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}


