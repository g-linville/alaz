#include "../headers/bpf.h"
#include "../headers/common.h"
#include "../headers/l7_req.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "http.c"
#include "amqp.c"
#include "postgres.c"

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define PROTOCOL_AMQP	2
#define PROTOCOL_POSTGRES	3

#define MAX_PAYLOAD_SIZE 512
#define PAYLOAD_PREFIX_SIZE 16

#define MAX_FDS_PER_PID 8192

// for rabbitmq methods
#define METHOD_PUBLISH           1
#define METHOD_DELIVER           2

char __license[] SEC("license") = "Dual MIT/GPL";


struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
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
    __uint(max_entries, 10240);
} l7_events SEC(".maps");

// when given with __type macro below
// type *btf.Pointer not supported
struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

// used for cases in which we don't have a read event
// we are only tracking write events.
// so we need to know when a write event is complete
// so we can send the l7 event to userspace
struct write_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 write_start_ns;  
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

// used for cases in which we only use write events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct write_args));
    __uint(max_entries, 10240);
} active_writes SEC(".maps");

// Processing enter of write and sendto syscalls
static __always_inline
int process_enter_of_syscalls_write_sendto(void* ctx, __u64 fd, char* buf, __u64 count){
    __u64 id = bpf_get_current_pid_tgid();
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);

    if (!req) {
        char msg[] = "Err: Could not get request from l7_request_heap";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }

    req->protocol = PROTOCOL_UNKNOWN;
    req->method = METHOD_UNKNOWN;
    req->request_type = 0;
    req->write_time_ns = bpf_ktime_get_ns();

    // TODO: If socket is not tcp (SOCK_STREAM), we are not interested in it

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;

    if(buf){
        // We are tracking tcp connections (sockets) on tcp_state bpf program, sending them to userspace
        // and then we are tracking http requests on this bpf program, sending them to userspace

        // We should not send l7_events that is not related to a tcp connection,
        // otherwise we will have a lot of events that are not related to a tcp connection
        // and we will not be able to match them with a tcp connection.
        // Also, file descriptors are reused, so tcp and udp sockets can have the same fd at different times.
        // This can cause mismatched events. (udp request with tcp connection)
        // Userspace only knows about tcp connections, so we should only send l7_events that are related to a tcp connection. 

        int method = parse_http_method(buf);
        if (method != -1){
            req->protocol = PROTOCOL_HTTP;
            req-> method = method;
        }else if (is_rabbitmq_publish(buf,count)){
            req->protocol = PROTOCOL_AMQP;
            req->method = METHOD_PUBLISH;
            struct write_args args = {};
            args.fd = fd;
            args.write_start_ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
        }else if (parse_client_postgres_data(buf, count, &req->request_type)){
            // TODO: should wait for CloseComplete message in case of statement close 
            if (req->request_type == POSTGRES_MESSAGE_CLOSE || req->request_type == POSTGRES_MESSAGE_TERMINATE){
                req->protocol = PROTOCOL_POSTGRES;
                req->method = METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE;
                struct write_args args = {};
                args.fd = fd;
                args.write_start_ns = bpf_ktime_get_ns();
                bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
            }
            req->protocol = PROTOCOL_POSTGRES;
        }else{
            req->protocol = PROTOCOL_UNKNOWN;
            req->method = METHOD_UNKNOWN;
            return 0; // do not continue processing for now (udp requests are flowing and overlaps with http requests)
        }
    }else{
        char msgCtx[] = "write buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        return 0;
    }

    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if(count > MAX_PAYLOAD_SIZE){
        // will not be able to copy all of it
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    }else{
        req->payload_size = count;
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


// Processing enter of read, recv, recvfrom syscalls
static __always_inline
int process_enter_of_syscalls_read_recvfrom(__u64 fd, char* buf, __u64 size) {
    __u64 id = bpf_get_current_pid_tgid();
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;

    // since a message consume in amqp does not have a prior write, we will not have a request in active_l7_requests
    // only in http, a prior write is needed, so we will have a request in active_l7_requests

    // void* active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    // if(!active_req) // if not found
    // {
    //     return 0;
    // }

    
    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.size = size;
    args.read_start_ns = bpf_ktime_get_ns();

    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if(res < 0)
    {
        char msg[] = "Error writing to active_reads - %ld";
        bpf_trace_printk(msg, sizeof(msg), res);
    }
    return 0;
}


static __always_inline
int process_exit_of_syscalls_write_sendto(void* ctx, __s64 ret){
    __u64 id = bpf_get_current_pid_tgid();
    
    // we only used this func for amqp, others will only be in active_l7_requests
    // used active_writes for cases that only depends on writes, like amqp publish
    // + postgres statement close, terminate
    struct write_args *active_write = bpf_map_lookup_elem(&active_writes, &id);
    if (!active_write) {
        bpf_map_delete_elem(&active_writes, &id);
        return 0;
    }

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = active_write->fd;

    // active_l7_requests 
    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if(!active_req) // if not found
    {
        return 0;
    }

    // write success
    if(ret>=0){
        // send l7 event
        int zero = 0;
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            bpf_map_delete_elem(&active_writes, &id);
            return 0;
        }

        e->protocol = active_req->protocol;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = active_req->method;
        if (e->protocol == PROTOCOL_POSTGRES && e->method == METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE){
            e->status = 1; // success
        }else{
            e->status = 0;
        }

        e->failed = 0; // success
        e->duration = bpf_ktime_get_ns()- active_write->write_start_ns; // total write time

        // request payload
        e->payload_size = active_req->payload_size;
        e->payload_read_complete = active_req->payload_read_complete;
        
        // copy req payload
        bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_writes, &id);

        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    }else{
        // write failed
        bpf_map_delete_elem(&active_writes, &id);
        bpf_map_delete_elem(&active_l7_requests, &k);
    }
    return 0;
}

static __always_inline
int process_exit_of_syscalls_read_recvfrom(void* ctx, __s64 ret) {
    if (ret < 0) { // read failed
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


        // clean up
        bpf_map_delete_elem(&active_reads, &id);
        bpf_map_delete_elem(&active_l7_requests, &k);

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


    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    // For a amqp consume, there will be no write, so we will not have a request in active_l7_requests
    // Process amqp consume first, if it is not amqp consume, look for a request in active_l7_requests

    if (is_rabbitmq_consume(read_info->buf, read_info->size)) {
        e->protocol = PROTOCOL_AMQP;
        e->method = METHOD_DELIVER;
        e->duration = bpf_ktime_get_ns()- read_info->read_start_ns;
        e->write_time_ns = read_info->read_start_ns; // TODO: it is not write time, but start of read time
        e->payload_size = 0;
        e->payload_read_complete = 0;
        e->failed = 0; // success
        e->status = 0;
        e->fd = k.fd;
        e->pid = k.pid;
        
        // reset payload
        for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {
            e->payload[i] = 0;
        }
        
        bpf_map_delete_elem(&active_reads, &id);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    }

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    e->fd = k.fd;
    e->pid = k.pid;

    e->method = active_req->method;

    e->protocol = active_req->protocol;
    e->duration = bpf_ktime_get_ns() - active_req->write_time_ns;
    
    e->write_time_ns = active_req->write_time_ns;
    
    // request payload
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    e->failed = 0; // success

    e->status = 0;
    if(read_info->buf && read_info->size > PAYLOAD_PREFIX_SIZE){
        if(e->protocol==PROTOCOL_HTTP){ // if http, try to parse status code
            // read first 16 bytes of read buffer
            char buf_prefix[PAYLOAD_PREFIX_SIZE];
            long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(read_info->buf)) ;
            
            if (r < 0) {
                char msg[] = "could not read into buf_prefix - %ld";
                bpf_trace_printk(msg, sizeof(msg), r);
                bpf_map_delete_elem(&active_reads, &id);
                return 0;
            }

            int status = parse_http_status(buf_prefix);
            if (status != -1){
                e->status = status;
            }
        }else if (e->protocol == PROTOCOL_POSTGRES){
            e->status = parse_postgres_server_resp(read_info->buf, ret);
            if (active_req->request_type == POSTGRES_MESSAGE_SIMPLE_QUERY) {
                e->method = METHOD_SIMPLE_QUERY;
            }
        }
    }else{
        char msgCtx[] = "read buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
       
    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        char msg[] = "could not write to l7_events - %ld";
        bpf_trace_printk(msg, sizeof(msg), r);
    }

    return 0;
}

// After socket creation and connection establishment, the kernel will call the
// write function of the socket's protocol handler to send data to the remote
// peer. The kernel will call the read function of the socket's protocol handler
// to receive data from the remote peer.

// Flow:
// 1. sys_enter_write
    // -- TODO: check if write was successful (return value), sys_exit_write ?
// 2. sys_enter_read
// 3. sys_exit_read


// In different programming languages, the syscalls might used in different combinations
// write - read
// send - recv
// sendto - recvfrom
// sendmmsg - recvfrom 
// sendmsg - recvmsg
// That's why we need to hook all of them
// and process the data in the same way

// sys_enter_ sending syscalls -- process_enter_of_syscalls_write_sendto
// sys_enter_ receiving syscalls -- process_enter_of_syscalls_read_recvfrom
// sys_exit_ receiving syscalls -- process_exit_of_syscalls_read_recvfrom


SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_write* ctx) {
   return process_enter_of_syscalls_write_sendto(ctx, ctx->fd, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_sendto* ctx) {
   return process_enter_of_syscalls_write_sendto(ctx, ctx->fd, ctx->buff, ctx->len);
}

SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct trace_event_raw_sys_exit_write* ctx) {
    return process_exit_of_syscalls_write_sendto(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct trace_event_raw_sys_exit_sendto* ctx) {
    return process_exit_of_syscalls_write_sendto(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_read* ctx) {
    return process_enter_of_syscalls_read_recvfrom(ctx->fd, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_recvfrom* ctx) {
    return process_enter_of_syscalls_read_recvfrom(ctx->fd, ctx->ubuf, ctx->size);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_read* ctx) {
    return process_exit_of_syscalls_read_recvfrom(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit_recvfrom* ctx) {
    return process_exit_of_syscalls_read_recvfrom(ctx, ctx->ret);
}
