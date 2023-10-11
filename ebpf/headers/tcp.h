struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

typedef unsigned short int sa_family_t;

struct sockaddr
{
  sa_family_t sa_family;
  char sa_data[14];
};

struct trace_event_sys_enter_connect
{
  struct trace_entry ent;
  int __syscall_nr;
  long unsigned int fd;
  struct sockaddr *uservaddr;
  long unsigned int addrlen;
};

struct trace_event_raw_sys_exit_read {
	__u64 unused;
	__s32 id;
	__s64 ret;
};

struct trace_event_raw_sys_exit_recvfrom {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct trace_event_raw_sys_exit_write {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct trace_event_raw_sys_exit_sendto {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

// TODO: remove unused fields ?
struct trace_event_raw_sys_enter_sendto {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    void * buff;
    __u64 len; // size_t ??
    __u64 flags;
    struct sockaddr * addr;
    __u64 addr_len;
};

struct trace_event_raw_sys_enter_read{
    struct trace_entry ent;
    int __syscall_nr;
    unsigned long int fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_enter_recvfrom {
    struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    void * ubuf;
    __u64 size;
    __u64 flags;
    struct sockaddr * addr;
    __u64 addr_len;
};


#define EVENT_TCP_ESTABLISHED	1
#define EVENT_TCP_CONNECT_FAILED		2
#define EVENT_TCP_LISTEN	3
#define EVENT_TCP_LISTEN_CLOSED	4
#define EVENT_TCP_CLOSED	5
