package command

import (
	"ctrace/config"
	"ctrace/ctrace"
	"fmt"
	"log"
	"strings"

	"github.com/urfave/cli/v2"
)

var traceCmd = &cli.Command{
	Name:  "trace",
	Usage: "trace containers",
	// Flags: []cli.Flag{
	// 	&cli.StringSliceFlag{
	// 		Name:    "event",
	// 		Aliases: []string{"e"},
	// 		Value:   nil,
	// 		Usage:   "trace only the specified event or syscall. use this flag multiple times to choose multiple events",
	// 	},
	// 	&cli.StringSliceFlag{
	// 		Name:  "exclude-event",
	// 		Value: nil,
	// 		Usage: "exclude an event from being traced. use this flag multiple times to choose multiple events to exclude",
	// 	},
	// },
	Flags: []cli.Flag{
		// &cli.BoolFlag{
		// 	Name:    "list",
		// 	Aliases: []string{"l"},
		// 	Value:   false,
		// 	Usage:   "just list tracable events",
		// },
		&cli.StringSliceFlag{
			Name:    "trace",
			Aliases: []string{"t"},
			Value:   nil,
			Usage:   "select events to trace by defining trace expressions. run '--trace help' for more info.",
		},
		// ...
	},

	Subcommands: []*cli.Command{
		listSubCmd,
	},

	Action: func(ctx *cli.Context) error {
		// if ctx.IsSet("event") && ctx.IsSet("exclude-event") {
		// 	return fmt.Errorf("'event' and 'exclude-event' can't be used in parallel")
		// }
		eventsNameToID := make(map[string]int32, len(ctrace.EventsIDToEvent))
		for _, event := range ctrace.EventsIDToEvent {
			eventsNameToID[event.Name] = event.ID
		}
		// events, err := prepareEventsToTrace(ctx.StringSlice("event"), ctx.StringSlice("exclude-event"), eventsNameToID)
		// if err != nil {
		// 	return err
		// }
		conf, err := config.GetConfigFromYml()
		if err != nil {
			return err
		}
		cfg := ctrace.CtraceConfig{
			// EventsToTrace:  events,
			OutputFormat:   string(conf.OutputFormat),
			PerfBufferSize: int(conf.PerfBufferSize),
			EventsPath:     string(conf.EventsPath),
			ErrorsPath:     string(conf.ErrorsPath),
		}
		log.Println("ctrace config loaded", ctx.StringSlice("trace"))
		filter, err := prepareFilter(ctx.StringSlice("trace"))
		if err != nil {
			return err
		}
		cfg.Filter = &filter

		t, err := ctrace.New(cfg)
		if err != nil {
			return fmt.Errorf("error creating Ctrace: %v", err)
		}
		return t.Run()
	},
}

func prepareEventsToTrace(eventFilter *ctrace.StringFilter, setFilter *ctrace.StringFilter, eventsNameToID map[string]int32) ([]int32, error) {
	eventFilter.Enabled = true
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res []int32
	setsToEvents := make(map[string][]int32)
	isExcluded := make(map[int32]bool)
	for id, event := range ctrace.EventsIDToEvent {
		// 通过这种方式拿到每种set对应的事件id
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
			// log.Println("set", set, id)
		}
	}
	for _, name := range excludeEvents {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to exclude: %s", name)
		}
		isExcluded[id] = true
	}
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]int32, 0, len(ctrace.EventsIDToEvent))
	for _, name := range eventsToTrace {
		id, ok := eventsNameToID[name]
		if !ok {
			return nil, fmt.Errorf("invalid event to trace: %s", name)
		}
		res = append(res, id)
	}
	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, fmt.Errorf("invalid set to trace: %s", set)
		}
		for _, id := range setEvents {
			if !isExcluded[id] {
				res = append(res, id)
			}
		}
	}
	return res, nil
}

// func prepareEventsToTrace(eventsToTrace []string, excludeEvents []string, eventsNameToID map[string]int32) ([]int32, error) {
// 	var res []int32
// 	isExcluded := make(map[int32]bool)

// 	if eventsToTrace == nil {
// 		for _, name := range excludeEvents {
// 			id, ok := eventsNameToID[name]
// 			if !ok {
// 				return nil, fmt.Errorf("invalid event to exclude: %s", name)
// 			}
// 			isExcluded[id] = true
// 		}
// 		res = make([]int32, 0, len(ctrace.EventsIDToEvent))
// 		for _, event := range ctrace.EventsIDToEvent {
// 			if !isExcluded[event.ID] {
// 				res = append(res, event.ID)
// 			}
// 		}
// 	} else {
// 		res = make([]int32, 0, len(ctrace.EventsIDToEvent))
// 		for _, name := range eventsToTrace {
// 			id, ok := eventsNameToID[name]
// 			if !ok {
// 				return nil, fmt.Errorf("invalid event to trace: %s", name)
// 			}
// 			log.Println("user set event " + name + " id " + strconv.FormatInt(int64(id), 10))
// 			res = append(res, id)
// 		}
// 	}
// 	return res, nil
// }

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

// TODO prepareFilter
func prepareFilter(filters []string) (ctrace.Filter, error) {

	filterHelp := `
Select which events to trace by defining trace expressions that operate on events or process metadata.
Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

Examples:
  --trace pid=new                                              | only trace events from new processes
  --trace pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --trace p=510 --trace p=1709                                 | only trace events from pid 510 or pid 1709 (same as above)
  --trace container=new                                        | only trace events from newly created containers
  --trace container                                            | only trace events from containers
  --trace c                                                    | only trace events from containers (same as above)
  --trace '!container'                                         | only trace events from the host
  --trace uid=0                                                | only trace events from uid 0
  --trace mntns=4026531840                                     | only trace events from mntns id 4026531840
  --trace pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --trace 'uid>0'                                              | only trace events from uids greater than 0
  --trace 'pid>0' --trace 'pid<1000'                           | only trace events from pids between 0 and 1000
  --trace 'u>0' --trace u!=1000                                | only trace events from uids greater than 0 but not 1000
  --trace event=execve,open                                    | only trace execve and open events
  --trace set=fs                                               | trace all file-system related events
  --trace s=fs --trace e!=open,openat                          | trace all file-system related events, but not open(at)
  --trace uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --trace comm=ls                                              | only trace events from ls command
  --trace close.fd=5                                           | only trace 'close' events that have 'fd' equals 5
  --trace openat.pathname=/tmp*                                | only trace 'openat' events that have 'pathname' prefixed by "/tmp"
  --trace openat.pathname!=/tmp/1,/bin/ls                      | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --trace comm=bash --trace follow                             | trace all events that originated from bash or from one of the processes spawned by bash


Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'
`

	if len(filters) == 1 && filters[0] == "help" {
		return ctrace.Filter{}, fmt.Errorf(filterHelp)
	}
	log.Println("进入prepareFilter", filters, len(filters))
	filter := ctrace.Filter{
		// UIDFilter: &ctrace.UintFilter{
		// 	Equal:    []uint64{},
		// 	NotEqual: []uint64{},
		// 	Less:     ctrace.LessNotSetUint,
		// 	Greater:  ctrace.GreaterNotSetUint,
		// 	Is32Bit:  true,
		// },
		// PIDFilter: &ctrace.UintFilter{
		// 	Equal:    []uint64{},
		// 	NotEqual: []uint64{},
		// 	Less:     ctrace.LessNotSetUint,
		// 	Greater:  ctrace.GreaterNotSetUint,
		// 	Is32Bit:  true,
		// },
		// NewPidFilter: &ctrace.BoolFilter{},
		// MntNSFilter: &ctrace.UintFilter{
		// 	Equal:    []uint64{},
		// 	NotEqual: []uint64{},
		// 	Less:     ctrace.LessNotSetUint,
		// 	Greater:  ctrace.GreaterNotSetUint,
		// },
		// PidNSFilter: &ctrace.UintFilter{
		// 	Equal:    []uint64{},
		// 	NotEqual: []uint64{},
		// 	Less:     ctrace.LessNotSetUint,
		// 	Greater:  ctrace.GreaterNotSetUint,
		// },
		// UTSFilter: &ctrace.StringFilter{
		// 	Equal:    []string{},
		// 	NotEqual: []string{},
		// },
		CommFilter: &ctrace.StringFilter{
			Equal:    []string{},
			NotEqual: []string{},
		},
		// ContFilter:    &ctrace.BoolFilter{},
		// NewContFilter: &ctrace.BoolFilter{},
		// RetFilter: &ctrace.RetFilter{
		// 	Filters: make(map[int32]ctrace.IntFilter),
		// },
		// ArgFilter: &ctrace.ArgFilter{
		// 	Filters: make(map[int32]map[string]ctrace.ArgFilterVal),
		// },
		EventsToTrace: []int32{},
	}

	eventFilter := &ctrace.StringFilter{Equal: []string{}, NotEqual: []string{}}
	setFilter := &ctrace.StringFilter{Equal: []string{}, NotEqual: []string{}}

	eventsNameToID := make(map[string]int32, len(ctrace.EventsIDToEvent))
	for _, event := range ctrace.EventsIDToEvent {
		eventsNameToID[event.Name] = event.ID
	}

	for _, f := range filters {
		filterName := f
		operatorAndValues := ""
		operatorIndex := strings.IndexAny(f, "=!<>")
		if operatorIndex > 0 {
			filterName = f[0:operatorIndex]
			operatorAndValues = f[operatorIndex:]
		}

		// if strings.Contains(f, ".retval") {
		// 	err := parseRetFilter(filterName, operatorAndValues, eventsNameToID, filter.RetFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if strings.Contains(f, ".") {
		// 	err := parseArgFilter(filterName, operatorAndValues, eventsNameToID, filter.ArgFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
		// Other filters should be given using their full name.
		// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
		if filterName == "comm" {
			err := parseStringFilter(operatorAndValues, filter.CommFilter)
			// log.Println(len(filters), filterName, operatorAndValues, setFilter)
			if err != nil {
				return ctrace.Filter{}, err
			}
			continue
		}

		// if strings.HasPrefix("container", f) || (strings.HasPrefix("!container", f) && len(f) > 1) {
		// 	filter.NewPidFilter.Enabled = true
		// 	filter.NewPidFilter.Value = true
		// 	err := parseBoolFilter(f, filter.ContFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if strings.HasPrefix("container", filterName) {
		// 	if operatorAndValues == "=new" {
		// 		filter.NewPidFilter.Enabled = true
		// 		filter.NewPidFilter.Value = true
		// 		filter.NewContFilter.Enabled = true
		// 		filter.NewContFilter.Value = true
		// 		continue
		// 	}
		// 	if operatorAndValues == "!=new" {
		// 		filter.ContFilter.Enabled = true
		// 		filter.ContFilter.Value = true
		// 		filter.NewPidFilter.Enabled = true
		// 		filter.NewPidFilter.Value = true
		// 		filter.NewContFilter.Enabled = true
		// 		filter.NewContFilter.Value = false
		// 		continue
		// 	}
		// }

		if strings.HasPrefix("event", filterName) {
			err := parseStringFilter(operatorAndValues, eventFilter)
			if err != nil {
				return ctrace.Filter{}, err
			}
			continue
		}

		// if filterName == "mntns" {
		// 	err := parseUintFilter(operatorAndValues, filter.MntNSFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if filterName == "pidns" {
		// 	err := parseUintFilter(operatorAndValues, filter.PidNSFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if strings.HasPrefix("pid", filterName) {
		// 	if operatorAndValues == "=new" {
		// 		filter.NewPidFilter.Enabled = true
		// 		filter.NewPidFilter.Value = true
		// 		continue
		// 	}
		// 	if operatorAndValues == "!=new" {
		// 		filter.NewPidFilter.Enabled = true
		// 		filter.NewPidFilter.Value = false
		// 		continue
		// 	}
		// 	err := parseUintFilter(operatorAndValues, filter.PIDFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// TODO set
		if strings.HasPrefix("set", filterName) {
			err := parseStringFilter(operatorAndValues, setFilter)
			log.Println(len(filters), filterName, operatorAndValues, setFilter)
			if err != nil {
				return ctrace.Filter{}, err
			}
			continue
		}
		// log.Println("jinqulk\n\n")
		// if filterName == "uts" {
		// 	err := parseStringFilter(operatorAndValues, filter.UTSFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if strings.HasPrefix("uid", filterName) {
		// 	err := parseUintFilter(operatorAndValues, filter.UIDFilter)
		// 	if err != nil {
		// 		return ctrace.Filter{}, err
		// 	}
		// 	continue
		// }

		// if strings.HasPrefix("follow", f) {
		// 	filter.Follow = true
		// 	continue
		// }

		return ctrace.Filter{}, fmt.Errorf("invalid filter option specified, use '--filter help' for more info")
	}

	var err error
	log.Println("eventFilter", eventFilter, setFilter)
	filter.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
	if err != nil {
		return ctrace.Filter{}, err
	}

	return filter, nil
}

func parseStringFilter(operatorAndValues string, stringFilter *ctrace.StringFilter) error {
	stringFilter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])  //取剩余参数
	operatorString := string(operatorAndValues[0]) //取第一个字符，看看是不等于还是等于

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")
	log.Println("parseStringFilter:", values)

	for i := range values {
		switch operatorString {
		case "=":
			stringFilter.Equal = append(stringFilter.Equal, values[i])
		case "!=":
			stringFilter.NotEqual = append(stringFilter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}
