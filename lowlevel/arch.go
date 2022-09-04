// SPDX-Licence-Identifier: MIT

package lowlevel

import "golang.org/x/sys/unix"

// GetAuditArch converts a GOARCH string (as in [runtime.GOARCH]) into its pendant
// in linux kernel audit identifier.
//
// If the given architecture string is unknown, GetAuditArch returns 0.
func GetAuditArch(goArch string) uint32 {
	switch goArch {
	case "386":
		return unix.AUDIT_ARCH_I386
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm":
		return unix.AUDIT_ARCH_ARM
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	case "armbe":
		return unix.AUDIT_ARCH_ARMEB
	case "loong64":
		return unix.AUDIT_ARCH_LOONGARCH64
	case "mips":
		return unix.AUDIT_ARCH_MIPS
	case "mips64":
		return unix.AUDIT_ARCH_MIPS64
	case "mips64le":
		return unix.AUDIT_ARCH_MIPSEL64
	case "mips64p32":
		return unix.AUDIT_ARCH_MIPS64N32
	case "mips64p32le":
		return unix.AUDIT_ARCH_MIPSEL64N32
	case "mipsle":
		return unix.AUDIT_ARCH_MIPSEL
	case "ppc":
		return unix.AUDIT_ARCH_PPC
	case "ppc64":
		return unix.AUDIT_ARCH_PPC64
	case "ppc64le":
		return unix.AUDIT_ARCH_PPC64LE
	case "riscv":
		return unix.AUDIT_ARCH_RISCV32
	case "riscv64":
		return unix.AUDIT_ARCH_RISCV64
	case "s390":
		return unix.AUDIT_ARCH_S390
	case "s390x":
		return unix.AUDIT_ARCH_S390X
	case "sparc":
		return unix.AUDIT_ARCH_SPARC
	case "sparc64":
		return unix.AUDIT_ARCH_SPARC64
	case "arm64be":
		return 0x800000b7
	default:
		return 0
	}
}

// ArchIs64Bits identifies whether the given GOARCH string is
// considered 64 bits by the linux kernel
func ArchIs64Bits(goArch string) bool {
	return GetAuditArch(goArch)&0x80000000 != 0
}

// ArchIs64Bits identifies whether the given GOARCH string is
// considered little endian by the linux kernel
func ArchIsLittleEndian(goArch string) bool {
	return GetAuditArch(goArch)&0x40000000 != 0
}
