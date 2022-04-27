package ctrace

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// PrintInodeMode prints the `mode` bitmask argument of the `mknod` syscall
// http://man7.org/linux/man-pages/man7/inode.7.html
func PrintInodeMode(mode uint32) string {
	var f []string

	// File Type
	switch {
	case mode&0140000 == 0140000:
		f = append(f, "S_IFSOCK")
	case mode&0120000 == 0120000:
		f = append(f, "S_IFLNK")
	case mode&0100000 == 0100000:
		f = append(f, "S_IFREG")
	case mode&060000 == 060000:
		f = append(f, "S_IFBLK")
	case mode&040000 == 040000:
		f = append(f, "S_IFDIR")
	case mode&020000 == 020000:
		f = append(f, "S_IFCHR")
	case mode&010000 == 010000:
		f = append(f, "S_IFIFO")
	}

	// File Mode
	// Owner
	if mode&00700 == 00700 {
		f = append(f, "S_IRWXU")
	} else {
		if mode&00400 == 00400 {
			f = append(f, "S_IRUSR")
		}
		if mode&00200 == 00200 {
			f = append(f, "S_IWUSR")
		}
		if mode&00100 == 00100 {
			f = append(f, "S_IXUSR")
		}
	}
	// Group
	if mode&00070 == 00070 {
		f = append(f, "S_IRWXG")
	} else {
		if mode&00040 == 00040 {
			f = append(f, "S_IRGRP")
		}
		if mode&00020 == 00020 {
			f = append(f, "S_IWGRP")
		}
		if mode&00010 == 00010 {
			f = append(f, "S_IXGRP")
		}
	}
	// Others
	if mode&00007 == 00007 {
		f = append(f, "S_IRWXO")
	} else {
		if mode&00004 == 00004 {
			f = append(f, "S_IROTH")
		}
		if mode&00002 == 00002 {
			f = append(f, "S_IWOTH")
		}
		if mode&00001 == 00001 {
			f = append(f, "S_IXOTH")
		}
	}

	return strings.Join(f, "|")
}

// PrintMemProt prints the `prot` bitmask argument of the `mmap` syscall
// http://man7.org/linux/man-pages/man2/mmap.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/mman-common.h#L10
func PrintMemProt(prot uint32) string {
	var f []string
	if prot == 0x0 {
		f = append(f, "PROT_NONE")
	} else {
		if prot&0x01 == 0x01 {
			f = append(f, "PROT_READ")
		}
		if prot&0x02 == 0x02 {
			f = append(f, "PROT_WRITE")
		}
		if prot&0x04 == 0x04 {
			f = append(f, "PROT_EXEC")
		}
	}
	return strings.Join(f, "|")
}

// PrintOpenFlags prints the `flags` bitmask argument of the `open` syscall
// http://man7.org/linux/man-pages/man2/open.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h
func PrintOpenFlags(flags uint32) string {
	var f []string

	//access mode
	switch {
	case flags&01 == 01:
		f = append(f, "O_WRONLY")
	case flags&02 == 02:
		f = append(f, "O_RDWR")
	default:
		f = append(f, "O_RDONLY")
	}

	// file creation and status flags
	if flags&0100 == 0100 {
		f = append(f, "O_CREAT")
	}
	if flags&0200 == 0200 {
		f = append(f, "O_EXCL")
	}
	if flags&0400 == 0400 {
		f = append(f, "O_NOCTTY")
	}
	if flags&01000 == 01000 {
		f = append(f, "O_TRUNC")
	}
	if flags&02000 == 02000 {
		f = append(f, "O_APPEND")
	}
	if flags&04000 == 04000 {
		f = append(f, "O_NONBLOCK")
	}
	if flags&04010000 == 04010000 {
		f = append(f, "O_SYNC")
	}
	if flags&020000 == 020000 {
		f = append(f, "O_ASYNC")
	}
	if flags&0100000 == 0100000 {
		f = append(f, "O_LARGEFILE")
	}
	if flags&0200000 == 0200000 {
		f = append(f, "O_DIRECTORY")
	}
	if flags&0400000 == 0400000 {
		f = append(f, "O_NOFOLLOW")
	}
	if flags&02000000 == 02000000 {
		f = append(f, "O_CLOEXEC")
	}
	if flags&040000 == 040000 {
		f = append(f, "O_DIRECT")
	}
	if flags&01000000 == 01000000 {
		f = append(f, "O_NOATIME")
	}
	if flags&010000000 == 010000000 {
		f = append(f, "O_PATH")
	}
	if flags&020000000 == 020000000 {
		f = append(f, "O_TMPFILE")
	}

	return strings.Join(f, "|")
}

// http://man7.org/linux/man-pages/man2/access.2.html
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/unistd.h.html#tag_13_77_03_04
func PrintAccessMode(mode uint32) string {
	var f []string
	if mode == 0x0 {
		f = append(f, "F_OK")
	} else {
		if mode&0x04 == 0x04 {
			f = append(f, "R_OK")
		}
		if mode&0x02 == 0x02 {
			f = append(f, "W_OK")
		}
		if mode&0x01 == 0x01 {
			f = append(f, "X_OK")
		}
	}
	return strings.Join(f, "|")
}

// PrintExecFlags prints the `flags` bitmask argument of the `execve` syscall
// http://man7.org/linux/man-pages/man2/axecveat.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/fcntl.h#L94
func PrintExecFlags(flags uint32) string {
	var f []string
	if flags&0x100 == 0x100 {
		f = append(f, "AT_EMPTY_PATH")
	}
	if flags&0x1000 == 0x1000 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if len(f) == 0 {
		f = append(f, "0")
	}
	return strings.Join(f, "|")
}

// PrintSocketType prints the `type` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h
func PrintSocketType(st uint32) string {
	var socketTypes = map[uint32]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}
	var f []string
	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}
	return strings.Join(f, "|")
}

// PrintSocketDomain prints the `domain` bitmask argument of the `socket` syscall
// http://man7.org/linux/man-pages/man2/socket.2.html
func PrintSocketDomain(sd uint32) string {
	var socketDomains = map[uint32]string{
		0:  "AF_UNSPEC",
		1:  "AF_UNIX",
		2:  "AF_INET",
		3:  "AF_AX25",
		4:  "AF_IPX",
		5:  "AF_APPLETALK",
		6:  "AF_NETROM",
		7:  "AF_BRIDGE",
		8:  "AF_ATMPVC",
		9:  "AF_X25",
		10: "AF_INET6",
		11: "AF_ROSE",
		12: "AF_DECnet",
		13: "AF_NETBEUI",
		14: "AF_SECURITY",
		15: "AF_KEY",
		16: "AF_NETLINK",
		17: "AF_PACKET",
		18: "AF_ASH",
		19: "AF_ECONET",
		20: "AF_ATMSVC",
		21: "AF_RDS",
		22: "AF_SNA",
		23: "AF_IRDA",
		24: "AF_PPPOX",
		25: "AF_WANPIPE",
		26: "AF_LLC",
		27: "AF_IB",
		28: "AF_MPLS",
		29: "AF_CAN",
		30: "AF_TIPC",
		31: "AF_BLUETOOTH",
		32: "AF_IUCV",
		33: "AF_RXRPC",
		34: "AF_ISDN",
		35: "AF_PHONET",
		36: "AF_IEEE802154",
		37: "AF_CAIF",
		38: "AF_ALG",
		39: "AF_NFC",
		40: "AF_VSOCK",
		41: "AF_KCM",
		42: "AF_QIPCRTR",
		43: "AF_SMC",
		44: "AF_XDP",
	}
	var res string
	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}
	return res
}

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable lenth slice, but that would case unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

// PrintCapability prints the `capability` bitmask argument of the `cap_capable` function
// include/uapi/linux/capability.h
func PrintCapability(cap int32) string {
	var capabilities = map[int32]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
	}
	var res string
	if capName, ok := capabilities[cap]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(cap))
	}
	return res
}

// PrintPrctlOption prints the `option` argument of the `prctl` syscall
// http://man7.org/linux/man-pages/man2/prctl.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/prctl.h
func PrintPrctlOption(op int32) string {
	var prctlOptions = map[int32]string{
		1:  "PR_SET_PDEATHSIG",
		2:  "PR_GET_PDEATHSIG",
		3:  "PR_GET_DUMPABLE",
		4:  "PR_SET_DUMPABLE",
		5:  "PR_GET_UNALIGN",
		6:  "PR_SET_UNALIGN",
		7:  "PR_GET_KEEPCAPS",
		8:  "PR_SET_KEEPCAPS",
		9:  "PR_GET_FPEMU",
		10: "PR_SET_FPEMU",
		11: "PR_GET_FPEXC",
		12: "PR_SET_FPEXC",
		13: "PR_GET_TIMING",
		14: "PR_SET_TIMING",
		15: "PR_SET_NAME",
		16: "PR_GET_NAME",
		19: "PR_GET_ENDIAN",
		20: "PR_SET_ENDIAN",
		21: "PR_GET_SECCOMP",
		22: "PR_SET_SECCOMP",
		23: "PR_CAPBSET_READ",
		24: "PR_CAPBSET_DROP",
		25: "PR_GET_TSC",
		26: "PR_SET_TSC",
		27: "PR_GET_SECUREBITS",
		28: "PR_SET_SECUREBITS",
		29: "PR_SET_TIMERSLACK",
		30: "PR_GET_TIMERSLACK",
		31: "PR_TASK_PERF_EVENTS_DISABLE",
		32: "PR_TASK_PERF_EVENTS_ENABLE",
		33: "PR_MCE_KILL",
		34: "PR_MCE_KILL_GET",
		35: "PR_SET_MM",
		36: "PR_SET_CHILD_SUBREAPER",
		37: "PR_GET_CHILD_SUBREAPER",
		38: "PR_SET_NO_NEW_PRIVS",
		39: "PR_GET_NO_NEW_PRIVS",
		40: "PR_GET_TID_ADDRESS",
		41: "PR_SET_THP_DISABLE",
		42: "PR_GET_THP_DISABLE",
		43: "PR_MPX_ENABLE_MANAGEMENT",
		44: "PR_MPX_DISABLE_MANAGEMENT",
		45: "PR_SET_FP_MODE",
		46: "PR_GET_FP_MODE",
		47: "PR_CAP_AMBIENT",
		50: "PR_SVE_SET_VL",
		51: "PR_SVE_GET_VL",
		52: "PR_GET_SPECULATION_CTRL",
		53: "PR_SET_SPECULATION_CTRL",
		54: "PR_PAC_RESET_KEYS",
		55: "PR_SET_TAGGED_ADDR_CTRL",
		56: "PR_GET_TAGGED_ADDR_CTRL",
	}

	var res string
	if opName, ok := prctlOptions[op]; ok {
		res = opName
	} else {
		res = strconv.Itoa(int(op))
	}
	return res
}

// PrintPtraceRequest prints the `request` argument of the `ptrace` syscall
// http://man7.org/linux/man-pages/man2/ptrace.2.html
// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ptrace.h
func PrintPtraceRequest(req int32) string {
	var ptraceRequest = map[int32]string{
		0:      "PTRACE_TRACEME",
		1:      "PTRACE_PEEKTEXT",
		2:      "PTRACE_PEEKDATA",
		3:      "PTRACE_PEEKUSER",
		4:      "PTRACE_POKETEXT",
		5:      "PTRACE_POKEDATA",
		6:      "PTRACE_POKEUSER",
		7:      "PTRACE_CONT",
		8:      "PTRACE_KILL",
		9:      "PTRACE_SINGLESTEP",
		12:     "PTRACE_GETREGS",
		13:     "PTRACE_SETREGS",
		14:     "PTRACE_GETFPREGS",
		15:     "PTRACE_SETFPREGS",
		16:     "PTRACE_ATTACH",
		17:     "PTRACE_DETACH",
		18:     "PTRACE_GETFPXREGS",
		19:     "PTRACE_SETFPXREGS",
		24:     "PTRACE_SYSCALL",
		0x4200: "PTRACE_SETOPTIONS",
		0x4201: "PTRACE_GETEVENTMSG",
		0x4202: "PTRACE_GETSIGINFO",
		0x4203: "PTRACE_SETSIGINFO",
		0x4204: "PTRACE_GETREGSET",
		0x4205: "PTRACE_SETREGSET",
		0x4206: "PTRACE_SEIZE",
		0x4207: "PTRACE_INTERRUPT",
		0x4208: "PTRACE_LISTEN",
		0x4209: "PTRACE_PEEKSIGINFO",
		0x420a: "PTRACE_GETSIGMASK",
		0x420b: "PTRACE_SETSIGMASK",
		0x420c: "PTRACE_SECCOMP_GET_FILTER",
		0x420d: "PTRACE_SECCOMP_GET_METADATA",
	}

	var res string
	if reqName, ok := ptraceRequest[req]; ok {
		res = reqName
	} else {
		res = strconv.Itoa(int(req))
	}
	return res
}
