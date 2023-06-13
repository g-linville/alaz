// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package tcp_state

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

const mapKey uint32 = 0

// padding to match the kernel struct
type tcpEvent struct {
	// sample_type int32
	// type_       int32
	// config      int32

	Fd        uint64
	Timestamp uint64
	Type      uint32
	Pid       uint32
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

func Deploy() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}
	defer objs.Close()

	// pinning a ebpf program
	// err := objs.bpfPrograms.GetCommand.Pin("/sys/fs/bpf/kprobe_execve_command")
	// if err != nil {
	// 	log.Default().Printf("could not pin program, %v", err)
	// }

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	time.Sleep(1 * time.Second)

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.bpfPrograms.InetSockSetState, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link inet_sock_set_state tracepoint")
	}
	defer l.Close()

	l1, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_connect tracepoint")
	}
	defer l1.Close()

	l2, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_connect tracepoint")
	}
	defer l2.Close()

	// initialize perf event readers
	tcpListenEvents, err := perf.NewReader(objs.TcpListenEvents, 64*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}
	tcpConnectEvents, err := perf.NewReader(objs.TcpConnectEvents, 64*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	go listenDebugMsgs()

	go func() {
		for range ticker.C {
			record, err := tcpListenEvents.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost %d samples", record.LostSamples)
			}

			bpfEvent := (*tcpEvent)(unsafe.Pointer(&record.RawSample[0]))

			log.Logger.Info().
				Uint32("pid", bpfEvent.Pid).
				Uint16("sport", bpfEvent.SPort).
				Uint16("dport", bpfEvent.DPort).
				Msg("listen event")
		}
	}()

	go func() {
		for range ticker.C {
			record, err := tcpConnectEvents.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost %d samples", record.LostSamples)
			}

			bpfEvent := (*tcpEvent)(unsafe.Pointer(&record.RawSample[0]))

			if bpfEvent.Type != 3 {
				continue
			}

			log.Logger.Info().
				Uint32("pid", bpfEvent.Pid).
				Uint64("fd", bpfEvent.Fd).
				Uint64("timestamp", bpfEvent.Timestamp).
				Uint16("sport", bpfEvent.SPort).
				Uint16("dport", bpfEvent.DPort).
				Str("saddr", fmt.Sprintf("%d.%d.%d.%d", bpfEvent.SAddr[0], bpfEvent.SAddr[1], bpfEvent.SAddr[2], bpfEvent.SAddr[3])).
				Str("daddr", fmt.Sprintf("%d.%d.%d.%d", bpfEvent.DAddr[0], bpfEvent.DAddr[1], bpfEvent.DAddr[2], bpfEvent.DAddr[3])).
				Msg("connect event")
		}
	}()

	select {}
}

func listenDebugMsgs() {
	printsPath := "/sys/kernel/debug/tracing/trace_pipe"

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fd, err := os.Open(printsPath)
	if err != nil {
		log.Logger.Warn().Err(err).Msg("error opening trace_pipe")
	}
	defer fd.Close()

	buf := make([]byte, 1024)
	for range ticker.C {
		n, err := fd.Read(buf)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error reading from trace_pipe")
		}
		log.Logger.Info().Msgf("read %d bytes: %s\n", n, buf[:n])
	}
}
