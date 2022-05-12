package command

import (
	"ctrace/config"
	"ctrace/ctrace"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

var traceCmd = &cli.Command{
	Name:  "trace",
	Usage: "trace containers",
	Flags: []cli.Flag{
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
			Name:  "show-exec-env",
			Value: false,
			Usage: "when tracing execve/execveat, show environment variables",
		},
	},
	Subcommands: []*cli.Command{
		listSubCmd,
	},
	Action: func(ctx *cli.Context) error {
		if ctx.IsSet("event") && ctx.IsSet("exclude-event") {
			return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
		}
		events, err := prepareEventsToTrace(ctx.StringSlice("event"), ctx.StringSlice("exclude-event"))
		if err != nil {
			return err
		}
		conf, err := config.GetConfigFromYml()
		if err != nil {
			return err
		}
		cfg := ctrace.CtraceConfig{
			EventsToTrace:         events,
			DetectOriginalSyscall: bool(conf.DetectOriginalSyscall),
			ShowExecEnv:           ctx.Bool("show-exec-env"),
			OutputFormat:          string(conf.OutputFormat),
			PerfBufferSize:        int(conf.PerfBufferSize),
			EventsPath:            string(conf.OutputPath),
			EventsFilePath:        os.Stdout,
			ErrorsPath:            os.Stderr,
		}
		capture := strings.Split(string(conf.Capture), "|")
		for _, cap := range capture {
			if cap == "write" {
				cfg.CaptureWrite = true
			} else if cap == "exec" {
				cfg.CaptureExec = true
			} else if cap == "mem" {
				cfg.CaptureMem = true
			} else if cap == "all" {
				cfg.CaptureWrite = true
				cfg.CaptureExec = true
				cfg.CaptureMem = true
			} else {
				return fmt.Errorf("invalid capture option: %s", cap)
			}
		}
		t, err := ctrace.New(cfg)
		if err != nil {
			return fmt.Errorf("error creating Ctrace: %v", err)
		}
		return t.Run()
	},
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

var listSubCmd = &cli.Command{
	Name:  "ls",
	Usage: "list trace info",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "container",
			Aliases: []string{"c"},
		},
	},
	Action: func(ctx *cli.Context) error {
		if ctx.NumFlags() == 0 {
			return fmt.Errorf("ls need to use with flag")
		}
		if ctx.Bool("container") {
			c := ctrace.InitContainers()
			if err := c.Populate(); err != nil {
				return fmt.Errorf("error initializing containers: %v", err)
			}
			fmt.Println(c.GetContainers())
		}
		return nil
	},
}
