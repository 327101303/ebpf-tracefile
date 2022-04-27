package ctrace

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"

	bpf "github.com/iovisor/gobpf/bcc"
)

// CtraceConfig is a struct containing user defined configuration of ctrace
type CtraceConfig struct {
	EventsToTrace         []int32
	DetectOriginalSyscall bool
	ShowExecEnv           bool
	OutputFormat          string
	//PerfBufferSize        int
	OutputPath   string
	CaptureWrite bool
	CaptureExec  bool
	CaptureMem   bool
	EventsFile   *os.File
	ErrorsFile   *os.File
}

type counter int32

type statsStore struct {
	eventCounter  counter
	errorCounter  counter
	lostEvCounter counter
	lostWrCounter counter
}

type Ctrace struct {
	config        CtraceConfig
	bpfModule     *bpf.Module
	eventsPerfMap *bpf.PerfMap
	eventsChannel chan []byte
	lostEvChannel chan uint64
	printer       eventPrinter
	stats         statsStore
	capturedFiles map[string]int64
	containers    *Containers
}

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
type context struct {
	Ts       uint64
	Pid      uint32
	Tid      uint32
	Ppid     uint32
	Uid      uint32
	Mnt_id   uint32
	Pid_id   uint32
	Comm     [16]byte
	Uts_name [16]byte
	Event_id int32
	Argc     uint8
	Argv     [128]byte
	Retval   int64
}

// Validate does static validation of the configuration
func (tc CtraceConfig) Validate() error {
	if tc.EventsToTrace == nil {
		return fmt.Errorf("eventsToTrace is nil")
	}
	if tc.OutputFormat != "table" && tc.OutputFormat != "json" && tc.OutputFormat != "gob" {
		return fmt.Errorf("unrecognized output format: %s", tc.OutputFormat)
	}
	for _, e := range tc.EventsToTrace {
		event, ok := EventsIDToEvent[e]
		if !ok {
			return fmt.Errorf("invalid event to trace: %d", e)
		}
		if event.Name == "reserved" {
			return fmt.Errorf("event is not implemented: %s", event.Name)
		}

	}
	// if (tc.PerfBufferSize & (tc.PerfBufferSize - 1)) != 0 {
	// 	return fmt.Errorf("invalid perf buffer size - must be a power of 2")
	// }
	return nil
}

// This var is supposed to be injected *at build time* with the contents of the ebpf c program
var ebpfProgramBase64Injected string

func getEBPFProgram() (string, error) {
	// if there's a local file, use it
	exePath, err := os.Getwd()
	if err != nil {
		return "", err
	}
	ebpfFilePath := filepath.Join(filepath.Dir(exePath), "./ctrace/ctrace/bpf/ctrace.bpf.c")
	_, err = os.Stat(ebpfFilePath)
	if !os.IsNotExist(err) {
		p, err := ioutil.ReadFile(ebpfFilePath)
		return string(p), err
	}
	// if there's no local file, try injected variable
	if ebpfProgramBase64Injected != "" {
		p, err := base64.StdEncoding.DecodeString(ebpfProgramBase64Injected)
		if err != nil {
			return "", err
		}
		return string(p), nil
	}
	return "", fmt.Errorf("could not find ebpf program")
}

func (c *counter) Increment(amount ...int) {
	sum := 1
	if len(amount) > 0 {
		sum = 0
		for _, a := range amount {
			sum = sum + a
		}
	}
	atomic.AddInt32((*int32)(c), int32(sum))
}

// New creates a new Ctrace instance based on a given valid CtraceConfig
func New(cfg CtraceConfig) (*Ctrace, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	if cfg.CaptureExec {
		essentialEvents[EventsNameToID["security_bprm_check"]] = false
	}
	if cfg.CaptureWrite {
		essentialEvents[EventsNameToID["vfs_write"]] = false
	}
	if cfg.CaptureMem {
		essentialEvents[EventsNameToID["mmap"]] = false
		essentialEvents[EventsNameToID["mprotect"]] = false
	}
	if cfg.CaptureMem {
		essentialEvents[EventsNameToID["mem_prot_alert"]] = false
	}
	t := &Ctrace{
		config: cfg,
	}
	t.printer = newEventPrinter(t.config.OutputFormat, t.config.EventsFile, t.config.ErrorsFile)

	p, err := getEBPFProgram()
	if err != nil {
		return nil, err
	}

	c := InitContainers()
	if err := c.Populate(); err != nil {
		return nil, fmt.Errorf("error initializing containers: %v", err)
	}
	t.containers = c

	err = t.initBPF(p)
	if err != nil {
		t.Close()
		return nil, err
	}

	t.capturedFiles = make(map[string]int64)
	return t, nil
}

func (t *Ctrace) initBPF(ebpfProgram string) error {
	var err error

	t.bpfModule = bpf.NewModule(ebpfProgram, []string{})

	chosenEvents := bpf.NewTable(t.bpfModule.TableId("chosen_events_map"), t.bpfModule)
	key := make([]byte, 4)
	leaf := make([]byte, 4)

	// compile final list of events to trace including essential events while at the same time record which essentials were requested by the user
	// to build this list efficiently we use the `tmpset` variable as follows:
	// 1. the presence of an entry says we have already seen this event (key)
	// 2. the value says if this event is essential
	eventsToTraceFinal := make([]int32, 0, len(t.config.EventsToTrace))
	tmpset := make(map[int32]bool, len(t.config.EventsToTrace))
	for e := range essentialEvents {
		eventsToTraceFinal = append(eventsToTraceFinal, e)
		tmpset[e] = true
	}
	for _, e := range t.config.EventsToTrace {
		// Set chosen events map according to events chosen by the user
		binary.LittleEndian.PutUint32(key, uint32(e))
		binary.LittleEndian.PutUint32(leaf, boolToUInt32(true))
		chosenEvents.Set(key, leaf)

		essential, exists := tmpset[e]
		// exists && essential = user requested essential
		// exists && !essential = dup event
		// !exists && essential = should never happen
		// !exists && !essential = user requested event
		if exists {
			if essential {
				essentialEvents[e] = true
			}
		} else {
			eventsToTraceFinal = append(eventsToTraceFinal, e)
			tmpset[e] = false
		}
	}

	//todo: attach probes
	//sysPrefix := bpf.GetSyscallPrefix()
	// for _, e := range eventsToTraceFinal {
	// 	event, ok := EventsIDToEvent[e]
	// 	if !ok {
	// 		continue
	// 	}
	// 	for _, probe := range event.Probes {
	// 		if probe.attach == sysCall {
	// 			kp, err := t.bpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", probe.fn))
	// 			if err != nil {
	// 				return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
	// 			}
	// 			err = t.bpfModule.AttachKprobe(sysPrefix+probe.event, kp, -1)
	// 			if err != nil {
	// 				return fmt.Errorf("error attaching kprobe %s: %v", probe.event, err)
	// 			}
	// 			kp, err = t.bpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", probe.fn))
	// 			if err != nil {
	// 				return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
	// 			}
	// 			err = t.bpfModule.AttachKretprobe(sysPrefix+probe.event, kp, -1)
	// 			if err != nil {
	// 				return fmt.Errorf("error attaching kretprobe %s: %v", probe.event, err)
	// 			}
	// 			continue
	// 		}
	// 		if probe.attach == kprobe {
	// 			kp, err := t.bpfModule.LoadKprobe(probe.fn)
	// 			if err != nil {
	// 				return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
	// 			}
	// 			err = t.bpfModule.AttachKprobe(probe.event, kp, -1)
	// 			if err != nil {
	// 				return fmt.Errorf("error attaching kprobe %s: %v", probe.event, err)
	// 			}
	// 			continue
	// 		}
	// 		if probe.attach == kretprobe {
	// 			kp, err := t.bpfModule.LoadKprobe(probe.fn)
	// 			if err != nil {
	// 				return fmt.Errorf("error loading kprobe %s: %v", probe.fn, err)
	// 			}
	// 			err = t.bpfModule.AttachKretprobe(probe.event, kp, -1)
	// 			if err != nil {
	// 				return fmt.Errorf("error attaching kretprobe %s: %v", probe.event, err)
	// 			}
	// 			continue
	// 		}
	// 		if probe.attach == tracepoint {
	// 			tp, err := t.bpfModule.LoadTracepoint(probe.fn)
	// 			if err != nil {
	// 				return fmt.Errorf("error loading tracepoint %s: %v", probe.fn, err)
	// 			}
	// 			err = t.bpfModule.AttachTracepoint(probe.event, tp)
	// 			if err != nil {
	// 				return fmt.Errorf("error attaching tracepoint %s: %v", probe.event, err)
	// 			}
	// 			continue
	// 		}
	// 	}
	// }

	// this is for test
	fnName := bpf.GetSyscallFnName("execve")

	kretprobe, err := t.bpfModule.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kretprobes documentation
	if err := t.bpfModule.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	//init ctrace configuration
	bpfConfig := bpf.NewTable(t.bpfModule.TableId("config_map"), t.bpfModule)

	binary.LittleEndian.PutUint32(key, uint32(configDetectOrigSyscall))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.DetectOriginalSyscall))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configExecEnv))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.ShowExecEnv))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configCaptureFiles))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.CaptureWrite))
	bpfConfig.Set(key, leaf)
	binary.LittleEndian.PutUint32(key, uint32(configExtractDynCode))
	binary.LittleEndian.PutUint32(leaf, boolToUInt32(t.config.CaptureMem))
	bpfConfig.Set(key, leaf)

	//todo: set containers_map
	eventsBPFTable := bpf.NewTable(t.bpfModule.TableId("events"), t.bpfModule)
	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	t.eventsPerfMap, err = bpf.InitPerfMap(eventsBPFTable, t.eventsChannel, t.lostEvChannel)
	//t.eventsPerfMap, err = bpf.InitPerfMapWithPageCnt(eventsBPFTable, t.eventsChannel, t.lostEvChannel, t.config.PerfBufferSize)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	return nil
}

// Run starts the trace. it will run until interrupted
func (t *Ctrace) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	t.printer.Preamble()
	t.eventsPerfMap.Start()
	go t.processEvents()
	<-sig
	t.eventsPerfMap.Stop()
	t.printer.Epilogue(t.stats)
	t.Close()
	return nil
}

// Close cleans up created resources
func (t Ctrace) Close() {
	if t.bpfModule != nil {
		t.bpfModule.Close()
	}
}

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

// shouldPrintEvent decides whether or not the given event id should be printed to the output
func (t Ctrace) shouldPrintEvent(e int32) bool {
	// if we got a trace for a non-essential event, it means the user explicitly requested it (using `-e`), or the user doesn't care (trace all by default). In both cases it's ok to print.
	// for essential events we need to check if the user actually wanted this event
	if print, isEssential := essentialEvents[e]; isEssential {
		return print
	}
	return true
}

func (t *Ctrace) processEvent(ctx *context, args []interface{}) error {
	eventName := EventsIDToEvent[ctx.Event_id].Name
	//show event name for raw_syscalls
	if eventName == "raw_syscalls" {
		if id, isInt32 := args[0].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				args[0] = event.Probes[0].event
			}
		}
	}

	return nil
}

func (t Ctrace) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.printer.Error(err)
}

func (t *Ctrace) processEvents() {
	for {
		select {
		case dataRaw := <-t.eventsChannel:
			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				t.handleError(err)
				continue
			}
			// for i := 0; i < int(ctx.Argc); i++ {
			// 	args[i], err = readArgFromBuff(dataBuff)
			// 	if err != nil {
			// 		t.handleError(err)
			// 		continue
			// 	}
			// }
			// err = t.processEvent(&ctx, args)
			// if err != nil {
			// 	t.handleError(err)
			// 	continue
			// }
			if t.shouldPrintEvent(ctx.Event_id) {
				t.stats.eventCounter.Increment()
				evt, err := newEvent(ctx, nil)
				if err != nil {
					t.handleError(err)
					continue
				}
				t.printer.Print(evt)
			}
		case lost := <-t.lostEvChannel:
			t.stats.lostEvCounter.Increment(int(lost))
		}
	}
}

func readContextFromBuff(buff io.Reader) (context, error) {
	var res context
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readArgTypeFromBuff(buff io.Reader) (argType, error) {
	var res argType
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	size, err := readInt32FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) //last byte is string terminating null
	defer func() {
		_, _ = readInt8FromBuff(buff) //discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
// max length can be passed as `max` to optimize memory allocation, otherwise pass 0
func readStringVarFromBuff(buff io.Reader, max int) (string, error) {
	var err error
	res := make([]byte, max)
	char, err := readInt8FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %v", err)
	}
	for count := 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		char, err = readInt8FromBuff(buff)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %v", err)
		}
	}
	res = bytes.TrimLeft(res[:], "\000")
	return string(res), nil
}

func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

func readInt8FromBuff(buff io.Reader) (int8, error) {
	var res int8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt8FromBuff(buff io.Reader) (uint8, error) {
	var res uint8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readInt16FromBuff(buff io.Reader) (int16, error) {
	var res int16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt16FromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt16BigendFromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

func readInt32FromBuff(buff io.Reader) (int32, error) {
	var res int32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt32FromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt32BigendFromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

func readInt64FromBuff(buff io.Reader) (int64, error) {
	var res int64
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readUInt64FromBuff(buff io.Reader) (uint64, error) {
	var res uint64
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readArgFromBuff(dataBuff io.Reader) (interface{}, error) {
	var err error
	var res interface{}
	at, err := readArgTypeFromBuff(dataBuff)
	if err != nil {
		return res, fmt.Errorf("error reading arg type: %v", err)
	}
	switch at {
	case intT:
		res, err = readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case uintT, devT:
		res, err = readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case longT:
		res, err = readInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case ulongT, offT, sizeT:
		res, err = readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strT:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strArrT:
		var ss []string
		// assuming there's at least one element in the array
		et, err := readArgTypeFromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading string array element type: %v", err)
		}
		for et != strArrT {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)

			et, err = readArgTypeFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string array element type: %v", err)
			}
		}
		res = ss
	case capT:
		cap, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading capability arg: %v", err)
		}
		res = PrintCapability(cap)
	case syscallT:
		sc, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading syscall arg: %v", err)
		}
		res = strconv.Itoa(int(sc))
		if event, ok := EventsIDToEvent[sc]; ok {
			if event.Probes[0].attach == sysCall {
				res = event.Probes[0].event
			}
		}
	case modeT:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintInodeMode(mode)
	case protFlagsT:
		prot, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintMemProt(prot)
	case pointerT:
		ptr, err := readUInt64FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = fmt.Sprintf("0x%X", ptr)
	case openFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintOpenFlags(flags)
	case accessModeT:
		mode, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintAccessMode(mode)
	case execFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintExecFlags(flags)
	case sockDomT:
		dom, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketDomain(dom)
	case sockTypeT:
		t, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintSocketType(t)
	case prctlOptT:
		op, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPrctlOption(op)
	case ptraceReqT:
		req, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = PrintPtraceRequest(req)
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return nil, fmt.Errorf("error unknown arg type %v", at)
	}
	return res, nil
}
