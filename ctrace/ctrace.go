package ctrace

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

// CtraceConfig is a struct containing user defined configuration of ctrace
type CtraceConfig struct {
	OutputFormat   string
	PerfBufferSize int
	EventsPath     string
	ErrorsPath     string
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
	eventsToTrace map[int32]bool
	eventsPerfMap *bpf.PerfBuffer
	eventsChannel chan []byte
	lostEvChannel chan uint64
	printer       eventPrinter
	stats         statsStore
	capturedFiles map[string]int64
	containers    *Containers
	DecParamName  [2]map[argTag]ArgMeta
	EncParamName  [2]map[string]argTag
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
	_        [3]byte
	Retval   int64
}

func UnameRelease() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}
	var buf [65]byte
	for i, b := range uname.Release {
		buf[i] = byte(b)
	}
	ver := string(buf[:])
	if i := strings.Index(ver, "\x00"); i != -1 {
		ver = ver[:i]
	}
	return ver
}

func supportRawTP() (bool, error) {
	ver := UnameRelease()
	if ver == "" {
		return false, fmt.Errorf("could not determine current release")
	}
	ver_split := strings.Split(ver, ".")
	if len(ver_split) < 2 {
		return false, fmt.Errorf("invalid version returned by uname")
	}
	major, err := strconv.Atoi(ver_split[0])
	if err != nil {
		return false, fmt.Errorf("invalid major number: %s", ver_split[0])
	}
	minor, err := strconv.Atoi(ver_split[1])
	if err != nil {
		return false, fmt.Errorf("invalid minor number: %s", ver_split[1])
	}
	if ((major == 4) && (minor >= 17)) || (major > 4) {
		return true, nil
	}
	return false, nil
}

// Validate does static validation of the configuration
func (tc CtraceConfig) Validate() error {
	if tc.EventsToTrace == nil {
		return fmt.Errorf("eventsToTrace is nil")
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
	return nil
}

func getEBPFProgramPath() (string, error) {
	// if there's a local file, use it
	exePath, err := os.Getwd()
	if err != nil {
		return "", err
	}
	ebpfFilePath := filepath.Join(exePath, "./dist/ctrace.bpf.o")
	_, err = os.Stat(ebpfFilePath)
	if !os.IsNotExist(err) {
		_, err := ioutil.ReadFile(ebpfFilePath)
		return ebpfFilePath, err
	}
	return "", fmt.Errorf("could not find ebpf.o")
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

type eventParam struct {
	encType argType
	encName argTag
}

func (t *Ctrace) initEventsParams() map[int32][]eventParam {
	eventsParams := make(map[int32][]eventParam)
	var seenNames [2]map[string]bool
	var ParamNameCounter [2]argTag
	seenNames[0] = make(map[string]bool)
	ParamNameCounter[0] = argTag(1)
	seenNames[1] = make(map[string]bool)
	ParamNameCounter[1] = argTag(1)
	paramT := noneT
	for id, params := range EventsIDToParams {
		for _, param := range params {
			switch param.Type {
			case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
				paramT = intT
			case "unsigned int", "u32":
				paramT = uintT
			case "long":
				paramT = longT
			case "unsigned long", "u64":
				paramT = ulongT
			case "off_t":
				paramT = offT
			case "mode_t":
				paramT = modeT
			case "dev_t":
				paramT = devT
			case "size_t":
				paramT = sizeT
			case "void*", "const void*":
				paramT = pointerT
			case "char*", "const char*":
				paramT = strT
			case "const char*const*", "const char**", "char**":
				paramT = strArrT
			case "const struct sockaddr*", "struct sockaddr*":
				paramT = sockAddrT
			default:
				// Default to pointer (printed as hex) for unsupported types
				paramT = pointerT
			}

			// As the encoded parameter name is u8, it can hold up to 256 different names
			// To keep on low communication overhead, we don't change this to u16
			// Instead, use an array of enc/dec maps, where the key is modulus of the event id
			// This can easilly be expanded in the future if required
			if !seenNames[id%2][param.Name] {
				seenNames[id%2][param.Name] = true
				t.EncParamName[id%2][param.Name] = ParamNameCounter[id%2]
				t.DecParamName[id%2][ParamNameCounter[id%2]] = param
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: ParamNameCounter[id%2]})
				ParamNameCounter[id%2]++
			} else {
				eventsParams[id] = append(eventsParams[id], eventParam{encType: paramT, encName: t.EncParamName[id%2][param.Name]})
			}
		}
	}

	if len(seenNames[0]) > 255 || len(seenNames[1]) > 255 {
		panic("Too many argument names given")
	}

	return eventsParams
}

func (t *Ctrace) populateBPFMaps() error {
	chosenEventsMap, _ := t.bpfModule.GetMap("chosen_events_map")
	for e, chosen := range t.eventsToTrace {
		// Set chosen events map according to events chosen by the user
		if chosen {
			chosenEventsMap.Update(e, boolToUInt32(true))
		}
	}

	eventsParams := t.initEventsParams()

	paramsTypesBPFMap, _ := t.bpfModule.GetMap("params_types_map")
	paramsNamesBPFMap, _ := t.bpfModule.GetMap("params_names_map")
	for e := range t.eventsToTrace {
		params := eventsParams[e]
		var paramsTypes uint64
		var paramsNames uint64
		for n, param := range params {
			paramsTypes = paramsTypes | (uint64(param.encType) << (8 * n))
			paramsNames = paramsNames | (uint64(param.encName) << (8 * n))
		}
		paramsTypesBPFMap.Update(e, paramsTypes)
		paramsNamesBPFMap.Update(e, paramsNames)
	}
	return nil
}

// New creates a new Ctrace instance based on a given valid CtraceConfig
func New(cfg CtraceConfig) (*Ctrace, error) {
	var err error

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation error: %v", err)
	}

	t := &Ctrace{
		config: cfg,
	}
	outf := os.Stdout
	if t.config.EventsPath != "" {
		dir := filepath.Dir(t.config.EventsPath)
		os.MkdirAll(dir, 0755)
		os.Remove(t.config.EventsPath)
		outf, err = os.Create(t.config.EventsPath)
		if err != nil {
			return nil, err
		}
	}
	errf := os.Stderr
	if t.config.ErrorsPath != "" {
		dir := filepath.Dir(t.config.ErrorsPath)
		os.MkdirAll(dir, 0755)
		os.Remove(t.config.ErrorsPath)
		errf, err = os.Create(t.config.ErrorsPath)
		if err != nil {
			return nil, err
		}
	}
	t.printer, err= newEventPrinter(t.config.OutputFormat, outf, errf)
	if err != nil {
		return nil, err
	}
	// c := InitContainers()
	// if err := c.Populate(); err != nil {
	// 	return nil, fmt.Errorf("error initializing containers: %v", err)
	// }
	// t.containers = c

	err = t.initBPF()
	if err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *Ctrace) initBPF() error {
	var err error
	ebpfProgram, err:= getEBPFProgramPath()
	if err!=nil {
		return err
	}
	t.bpfModule, err = bpf.NewModuleFromFile(ebpfProgram)
	if err != nil {
		return fmt.Errorf("error creating bpf module from %s, %v", ebpfProgram, err)
	}
	supportRawTracepoints, err := supportRawTP()
	if err != nil {
		return fmt.Errorf("Failed to find kernel version: %v", err)
	}
	for _, event := range EventsIDToEvent {
		for _, probe := range event.Probes {
			prog, _ := t.bpfModule.GetProgram(probe.fn)
			if prog == nil && probe.attach == sysCall {
				prog, _ = t.bpfModule.GetProgram(fmt.Sprintf("syscall__%s", probe.fn))
			}
			if prog == nil {
				continue
			}
			if _, ok := t.eventsToTrace[event.ID]; !ok {
				// This event is not being traced - set its respective program(s) "autoload" to false
				err = prog.SetAutoload(false)
				if err != nil {
					return err
				}
				continue
			}
			// As kernels < 4.17 don't support raw tracepoints, set these program types to "regular" tracepoint
			if !supportRawTracepoints && (prog.GetType() == bpf.BPFProgTypeRawTracepoint) {
				err = prog.SetTracepoint()
				if err != nil {
					return err
				}
			}
		}
	}

	err = t.bpfModule.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("error loading object from bpf module, %v", err)
	}

	err = t.populateBPFMaps()
	if err != nil {
		return fmt.Errorf("error populating ebpf map, %v", err)
	}

	for e, _ := range t.eventsToTrace {
		event, ok := EventsIDToEvent[e]
		if !ok {
			continue
		}
		for _, probe := range event.Probes {
			if probe.attach == sysCall {
				// Already handled by raw_syscalls tracepoints
				continue
			}
			prog, err := t.bpfModule.GetProgram(probe.fn)
			if err != nil {
				return fmt.Errorf("error getting program %s: %v", probe.fn, err)
			}
			if probe.attach == rawTracepoint && !supportRawTracepoints {
				// We fallback to regular tracepoint in case kernel doesn't support raw tracepoints (< 4.17)
				probe.attach = tracepoint
			}
			switch probe.attach {
			case kprobe:
				// todo: after updating minimal kernel version to 4.18, use without legacy
				_, err = prog.AttachKprobeLegacy(probe.event)
			case kretprobe:
				// todo: after updating minimal kernel version to 4.18, use without legacy
				_, err = prog.AttachKretprobeLegacy(probe.event)
			case tracepoint:
				_, err = prog.AttachTracepoint(probe.event)
			case rawTracepoint:
				tpEvent := strings.Split(probe.event, ":")[1]
				_, err = prog.AttachRawTracepoint(tpEvent)
			}
			if err != nil {
				return fmt.Errorf("error attaching event %s: %v", probe.event, err)
			}
		}
	}

	//todo: set containers_map
	t.eventsChannel = make(chan []byte, 1000)
	t.lostEvChannel = make(chan uint64)
	t.eventsPerfMap, err = t.bpfModule.InitPerfBuf("events", t.eventsChannel, t.lostEvChannel, t.config.PerfBufferSize)
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
	go t.processLostEvents()
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
	t.printer.Close()
}

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

func copyFileByPath(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}

func (t *Ctrace) prepareArgsForPrint(ctx *context, args map[argTag]interface{}) error {
	for key, arg := range args {
		if ptr, isUintptr := arg.(uintptr); isUintptr {
			args[key] = fmt.Sprintf("0x%X", ptr)
		}
	}
	switch ctx.Event_id {
	case SysEnterEventID, SysExitEventID, CapCapableEventID:
		//show syscall name instead of id
		if id, isInt32 := args[t.EncParamName[ctx.Event_id%2]["syscall"]].(int32); isInt32 {
			if event, isKnown := EventsIDToEvent[id]; isKnown {
				if event.Probes[0].attach == sysCall {
					args[t.EncParamName[ctx.Event_id%2]["syscall"]] = event.Probes[0].event
				}
			}
		}
		if ctx.Event_id == CapCapableEventID {
			if cap, isInt32 := args[t.EncParamName[ctx.Event_id%2]["cap"]].(int32); isInt32 {
				args[t.EncParamName[ctx.Event_id%2]["cap"]] = PrintCapability(cap)
			}
		}
	case MmapEventID, MprotectEventID, PkeyMprotectEventID:
		if prot, isInt32 := args[t.EncParamName[ctx.Event_id%2]["prot"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["prot"]] = PrintMemProt(uint32(prot))
		}
	case PtraceEventID:
		if req, isInt64 := args[t.EncParamName[ctx.Event_id%2]["request"]].(int64); isInt64 {
			args[t.EncParamName[ctx.Event_id%2]["request"]] = PrintPtraceRequest(req)
		}
	case PrctlEventID:
		if opt, isInt32 := args[t.EncParamName[ctx.Event_id%2]["option"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["option"]] = PrintPrctlOption(opt)
		}
	case SocketEventID:
		if dom, isInt32 := args[t.EncParamName[ctx.Event_id%2]["domain"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["domain"]] = PrintSocketDomain(uint32(dom))
		}
		if typ, isInt32 := args[t.EncParamName[ctx.Event_id%2]["type"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["type"]] = PrintSocketType(uint32(typ))
		}
	case ConnectEventID, AcceptEventID, Accept4EventID, BindEventID, GetsocknameEventID:
		if sockAddr, isStrMap := args[t.EncParamName[ctx.Event_id%2]["addr"]].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[t.EncParamName[ctx.Event_id%2]["addr"]] = s
		}
	case AccessEventID, FaccessatEventID:
		if mode, isInt32 := args[t.EncParamName[ctx.Event_id%2]["mode"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["mode"]] = PrintAccessMode(uint32(mode))
		}
	case ExecveatEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintExecFlags(uint32(flags))
		}
	case OpenEventID, OpenatEventID, SecurityFileOpenEventID:
		if flags, isInt32 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintOpenFlags(uint32(flags))
		}
	case MknodEventID, MknodatEventID, ChmodEventID, FchmodEventID, FchmodatEventID:
		if mode, isUint32 := args[t.EncParamName[ctx.Event_id%2]["mode"]].(uint32); isUint32 {
			args[t.EncParamName[ctx.Event_id%2]["mode"]] = PrintInodeMode(mode)
		}
	case MemProtAlertEventID:
		if alert, isAlert := args[t.EncParamName[ctx.Event_id%2]["alert"]].(alert); isAlert {
			args[t.EncParamName[ctx.Event_id%2]["alert"]] = PrintAlert(alert)
		}
	case CloneEventID:
		if flags, isUint64 := args[t.EncParamName[ctx.Event_id%2]["flags"]].(uint64); isUint64 {
			args[t.EncParamName[ctx.Event_id%2]["flags"]] = PrintCloneFlags(flags)
		}
	case SendtoEventID, RecvfromEventID:
		addrTag := t.EncParamName[ctx.Event_id%2]["dest_addr"]
		if ctx.Event_id == RecvfromEventID {
			addrTag = t.EncParamName[ctx.Event_id%2]["src_addr"]
		}
		if sockAddr, isStrMap := args[addrTag].(map[string]string); isStrMap {
			var s string
			for key, val := range sockAddr {
				s += fmt.Sprintf("'%s': '%s',", key, val)
			}
			s = strings.TrimSuffix(s, ",")
			s = fmt.Sprintf("{%s}", s)
			args[addrTag] = s
		}
	case BpfEventID:
		if cmd, isInt32 := args[t.EncParamName[ctx.Event_id%2]["cmd"]].(int32); isInt32 {
			args[t.EncParamName[ctx.Event_id%2]["cmd"]] = PrintBPFCmd(cmd)
		}
	}

	return nil
}



func (t *Ctrace) processLostEvents() {
	for {
		lost := <-t.lostEvChannel
		t.stats.lostEvCounter.Increment(int(lost))
	}
}


