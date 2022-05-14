# ctrace
## how to build ctrace
Kernel version >= 5.10
`$sudo apt install build-essential git make libelf-dev strace tar bpfcc-tools libbpf-dev linux-headers-$(uname -r)  linux-tools-common gcc-`
`$sudo apt install clang llvm`
configure the environment of building and running libbpf-go ebpf program first
`$make build`
you can use blow cmd to clean
`$make clean`
more details see Makefile

## how to run ctrace
1. build ctrace first
2. `sudo ./dist/ctrace` to run the CLI
3. the HELP INFO shows the intructions

## design overview
1. ctrace used libbpf+BPF CO-RE to implement CORE feature
2. ctrace entrance: main.go
3. main.go calls cli.App to run the command line applicaion
4. all commands are define under /command
5. the /command/common.go defines the global flags/action
6. the /command/config.go defines the command to set trace configuration, and the /config/config.go includes supported settings
7. /ctrace/bpf contains the ebpf files, including macro definition, vmlinux file, and bpf program source code
8. /argprinters.go defines how to print various events
9. /consts.go defines the events could be traced, according to libbpf
10. /container.go defines all struct and func about container
11. /external.go defines Event struct, which represents the event concept
12. ctrace.go defines the userspace functions

报告内容：
1. 前期调研：
通过各类论坛搜索ebpf介绍及使用教学，了解学习了ebpf工具的意义及使用方法。在本项目采用哪种库工具来与ebpf进行交互的讨论中，决定在gobpf、libbpf-go及cilium库中进行选择。最终为贴近实际项目，实现CO-RE特性，选择了libbpf-go作为开发工具，并进行了相关知识的学习。
2. 导师情况：
已与校外导师取得联系并添加了微信，并在校内找到了做云计算相关方向的老师作为指导老师。均建立起了稳定的沟通渠道。
3. 当前开发状况：
现已大致完成项目（proj118）要求的第二项即容器对系统的调用，正研究另外两项功能涉及的跟踪函数与跟踪点。
4. 当前困难：
不清楚容器间互访具体是互访什么、如何互访；容器哪些行为比较重要应重点关注；没有接触过容器在商业领域的使用，对容器上执行的业务以及对应的权限需求了解很少。