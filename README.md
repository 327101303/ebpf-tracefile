# ctrace
## how to build ctrace
`$make build`
`$make clean`
more details see Makefile

## how to run ctrace
1. build ctrace first
2. `sudo ./tar.ctrace` to run the CLI
3. the HELP INFO shows the intructions

## design overview
1. ctrace entrance: main.go
2. main.go calls cli.App to run the command line applicaion
3. all commands are define under /ctrace/command
4. the /ctrace/command/common.go defines the global flags/action
5. /ctrace/bpf/ctrace.bpf.c defines the ebpf functions
6. ctrace.go defines the userspace functions
