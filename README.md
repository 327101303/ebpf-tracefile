[TOC]

# 项目介绍

ctrace实现了一个基于eBPF的容器跟踪工具和权限最小集分配工具，用于帮助用户跟踪容器行为、防范恶意攻击。它可以跟踪已存在和新开启的容器，收集各类信息并打印或以json文件的形式储存。同时它可以根据容器的行为通过linux系统的seccomp功能自动为容器分配权限最小集。ctrace的主要功能如下：

1.  采集数据：使用Linux系统的eBPF技术对容器进行筛选跟踪与数据采集。
2.  数据存储：将采集获得的数据按一定格式存储到json文件中。
3.  权限最小集分配：使用seccomp技术根据json文件中跟踪到的系统调用来给容器分配权限。

## 项目特点

- 实现353个系统调用+3个rawTracepoint+vfs kprobe

- ctrace并没有采用相对比较成熟的BCC开发模式，而是使用libbpfgo框架进行开发，从而实现了CORE特性，摆脱了对内核版本的依赖（但仍需5.10以上的内核版本），使得eBPF程序的开发可以更加专注于功能本身而不是某个结构/函数是否随内核版本发生了改变。go语言用于用户程序开发也更易与当今云原生主流应用对接。

# 项目规划

| 时间                  | 任务                                          | 达成情况 |
| --------------------- | --------------------------------------------- | -------- |
| 2022/4/20 - 2022/5/2  | 学习eBPF相关知识，确定项目实现方式            | 完成     |
| 2022/5/3 - 2022/5/4   | 搭建项目开发环境                              | 完成     |
| 2022/5/5 - 2022/5/8   | 设计编写程序基础框架                          | 完成     |
| 2022/5/9 - 2022/5/13  | 实现指定跟踪容器功能                          | 完成     |
| 2022/5/14 - 2022/5/15 | 更换项目实现方式为libbpf-go                   | 完成     |
| 2022/5/16 - 2022/5/21 | 实现跟踪容器系统调用功能                      | 完成     |
| 2022/5/22 - 2022/5/26 | 实现跟踪容器文件访问功能                      | 完成     |
| 2022/5/27 - 2022/5/28 | 实现记录跟踪数据存储功能                      | 完成     |
| 2022/5/29 - 2022/6/4  | 过程文档编写完善                              | 进行     |
| 2022/6/3 - 2022/6/15  | 实现跟踪容器间互访功能                        | 进行     |
| 2022/6/16 - 2022/6/20 | 实现使用seccomp自动读取数据分配权限最小集功能 | 待办     |

# Quickstart

## 环境准备

- make
- clang-12
- libbpf
- linux-tools-common
- go 1.14+
- kernel version：5.10+

## 编译运行

1. `make build`
2. 运行ctrace，监控容器行为

```bash
# 是否跟踪容器内openat系统调用
sudo ./dist/ctrace trace --event openat
sudo ./dist/ctrace trace --exclude-event openat

# 是否跟踪容器内文件系统、网络、进程相关事件
sudo ./dist/ctrace trace --set fs/net/proc
sudo ./dist/ctrace trace --exclude-set fs/net/proc

# 是否过滤掉容器内进程名为comm的相关事件
sudo ./dist/ctrace trace --comm bash
sudo ./dist/ctrace trace --exclude-comm bash

# 跟踪容器所有系统调用，不跟踪文件系统相关事件
sudo ./dist/ctrace trace --event sys_enter --exclude-set fs

# 跟踪容器内文件系统相关事件，过滤掉read事件
sudo ./dist/ctrace trace --set fs  --exclude-event read

# 跟踪容器所有系统调用，不跟踪文件系统相关事件，只跟踪bash进程
sudo ./dist/ctrace trace --exclude-set fs --comm bash

# 实现docker ps，列出正在运行的容器
sudo ./dist/ctrace trace ls -c
```

![openat](../picture/openat-16544392571046.png)

3. config配置输出

```bash
# 设置输出格式为json或table
sudo ./dist/ctrace config --set output-format=json

# 设置输出文件路径，不设置则输出到终端屏幕
sudo ./dist/ctrace config --set events-path=~/ctrace_output/events.json

# 设置错误事件输出文件路径
sudo ./dist/ctrace config --set errors-path=~/ctrace_output/error.json
```



# **功能实现**

## eBPF入门

[eBPF入门](./doc/eBPF入门.md)

## 功能设计与实现

### 概要设计

通过阅读eBPF相关文章、学习类似项目经验，我们决定使用libbpf-go作为ctrace的实现方式。首先编写eBPF程序跟踪记录内核中各个进程进行的系统调用和文件访问等行为，分别对其编写函数并进行相应处理。随后根据cgroup id将容器进程挑选出来，再通过eBPF Map将采集到的信息传递给用户空间程序进一步的处理。用户程序则负责格式化打印储存event信息、跟踪选项设置、容器权限配置等功能的实现。程序架构如下所示：

![程序架构](https://s2.loli.net/2022/06/05/2jvIH9z7J3FtV14.png)

### cli实现

[cli实现](./doc/cli实现.md)

### 功能实现

[容器对文件的访问、系统调用、容器互访](./doc/功能实现.md)

### 事件输出

[事件输出](./doc/事件输出.md)

## 功能测试

[功能测试](./doc/功能测试.md)



## 遇到的问题及解决方法

- 怎么通过文件描述符找到文件名？

- cli的StringSlice对逗号的处理导致flag不能同时接收多个参数。2.5.0版本会把StringSliceFlag的逗号分开，当作下一个flag
- 怎么实现docker ps？
- makefile中伪target不能检测生成文件的改动，导致冗余编译。使用变量代替字符串target，实现.o文件名与target名一致
- clang编译器对于#ifdef、#if defined的行为不一样，#ifdef XXX，如果XXX没定义会报错，但是使用#if defined XXX的话，如果XXX没定义不会报错，会走else
- error: Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map

### ...

# 团队介绍

企业导师：程泽睿志（华为）

学习导师：吴松（华中科技大学）

成员与分工：

- 洪涛：系统调用实现、config模块编写、跟踪容器内事件
- 郭永强：文件系统事件、容器互访实现
- 吴浩：过程文档整理、项目整体测试

联系我们：BaldStrong@qq.com

# 参考引用

- [Linux内核调试技术——kprobe使用与实现](https://blog.csdn.net/luckyapple1028/article/details/52972315)
- [BPF之路一bpf系统调用](https://www.anquanke.com/post/id/263803)
- [BPF的可移植性和CO-RE (Compile Once – Run Everywhere）](https://www.cnblogs.com/charlieroro/p/14206214.html)





# 中期检查README

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