package command

import (
	"ctrace/ctrace"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

var Commands = []*cli.Command{
	// more subcommands ...
}

var GlobalOptions = []cli.Flag{
	&cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Value:   "table",
		Usage:   "output format: table/json/gob",
	},
	&cli.StringSliceFlag{
		Name:    "event",
		Aliases: []string{"e"},
		Value:   nil,
		Usage:   "trace only the specified event or syscall. use this flag multiple times to choose multiple events",
	},
	&cli.StringSliceFlag{
		Name:  "exclude-event",
		Value: nil,
		Usage: "exclude an event from being traced. use this flag multiple times to choose multiple events to exclude",
	},
	&cli.BoolFlag{
		Name:  "detect-original-syscall",
		Value: false,
		Usage: "when tracing kernel functions which are not syscalls (such as cap_capable), detect and show the original syscall that called that function",
	},
	&cli.BoolFlag{
		Name:  "show-exec-env",
		Value: false,
		Usage: "when tracing execve/execveat, show environment variables",
	},
	&cli.IntFlag{
		Name:    "perf-buffer-size",
		Aliases: []string{"b"},
		Value:   64,
		Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
	},
	&cli.BoolFlag{
		Name:    "show-all-syscalls",
		Aliases: []string{"a"},
		Value:   false,
		Usage:   "log all syscalls invocations, including syscalls which were not fully traced by tracee (shortcut to -e raw_syscalls)",
	},
	&cli.StringFlag{
		Name:  "output-path",
		Value: "/tmp/ctrace",
		Usage: "set output path",
	},
	&cli.StringSliceFlag{
		Name:  "capture",
		Value: nil,
		Usage: "capture artifacts that were written, executed or found to be suspicious. captured artifacts will appear in the 'output-path' directory. possible values: 'write'/'exec'/'mem'/'all'. use this flag multiple times to choose multiple capture options",
	},
}

// ErrPrintAndExit 表示遇到需要打印信息并提前退出的情形，不需要打印错误信息
var ErrPrintAndExit = errors.New("print and exit")

// global action
var GlobalAction = func(ctx *cli.Context) error {
	if ctx.IsSet("event") && ctx.IsSet("exclude-event") {
		return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
	}
	events, err := prepareEventsToTrace(ctx.StringSlice("event"), ctx.StringSlice("exclude-event"))
	if err != nil {
		return err
	}
	cfg := ctrace.CtraceConfig{
		EventsToTrace:         events,
		DetectOriginalSyscall: ctx.Bool("detect-original-syscall"),
		ShowExecEnv:           ctx.Bool("show-exec-env"),
		OutputFormat:          ctx.String("output"),
		//PerfBufferSize:        ctx.Int("perf-buffer-size"),
		OutputPath: ctx.String("output-path"),
		EventsFile: os.Stdout,
		ErrorsFile: os.Stderr,
	}
	capture := ctx.StringSlice("capture")
	for _, cap := range capture {
		if cap == "write" {
			cfg.CaptureWrite = true
			fmt.Println("you've set CaptureWrite")
		} else if cap == "exec" {
			cfg.CaptureExec = true
			fmt.Println("you've set CaptureExec")
		} else if cap == "mem" {
			cfg.CaptureMem = true
			fmt.Println("you've set CaptureMem")
		} else if cap == "all" {
			cfg.CaptureWrite = true
			cfg.CaptureExec = true
			cfg.CaptureMem = true
			fmt.Println("you've set all")
		} else {
			return fmt.Errorf("invalid capture option: %s", cap)
		}
	}
	if ctx.Bool("show-all-syscalls") {
		cfg.EventsToTrace = append(cfg.EventsToTrace, ctrace.EventsNameToID["raw_syscalls"])
	}
	t, err := ctrace.New(cfg)
	if err != nil {
		return fmt.Errorf("error creating Ctrace: %v", err)
	}
	return t.Run()
}

func prepareEventsToTrace(eventsToTrace []string, excludeEvents []string) ([]int32, error) {
	var res []int32
	if eventsToTrace == nil {
		for _, name := range excludeEvents {
			id, ok := ctrace.EventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to exclude: %s", name)
			}
			event := ctrace.EventsIDToEvent[id]
			event.EnabledByDefault = false
			ctrace.EventsIDToEvent[id] = event
		}
		res = make([]int32, 0, len(ctrace.EventsIDToEvent))
		for _, event := range ctrace.EventsIDToEvent {
			if event.EnabledByDefault {
				res = append(res, event.ID)
			}
		}
	} else {
		res = make([]int32, 0, len(eventsToTrace))
		for _, name := range eventsToTrace {
			id, ok := ctrace.EventsNameToID[name]
			if !ok {
				return nil, fmt.Errorf("invalid event to trace: %s", name)
			}
			res = append(res, id)
		}
	}
	return res, nil
}
