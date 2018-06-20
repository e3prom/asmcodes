# Shellcode
This repository holds a collection of asmcodes (or more commonly called 'shellcodes') I wrote for various operating systems, architectures and CPU instruction sets.

All shellcodes are null free so they can be transmitted inside buffers and over common protocols without being null-terminated. Keep in mind that most shellcodes have not been optimized in terms of length and portability, however they are still interesting for educational purposes as you can easily read them and understand their behavior and how they works. The asmcodes can also be used as a reference for further improvements or for studying shellcode development.

## Shellcodes Assembly
Unless otherwise stated in the comment block of the source files, all shellcodes can be assembled using the [NASM](http://www.nasm.us) assembler.

## Quick View
```
.
├── dev
│   ├── generic-stack-overflow-argv.c
│   ├── generic-stack-overflow.c
│   ├── generic-stack-overflow-file.c
│   └── ret2libc-stack-overflow.c
├── linux-x86
│   ├── lnx-bind-sctp-execve-shrt-x86_32.s
│   ├── lnx-bind-sctp-execve-x86_32.s
│   ├── lnx-bind-tcp-execve-x86_32.s
│   ├── lnx-connback-sctp-execve-x86_32.s
│   ├── lnx-connback-tcp-execve-x86_32.s
│   ├── lnx-execve-callsub-x86_32.s
│   ├── lnx-execve-cdq-xchg-x86_32.s
│   ├── lnx-execve-setreuid-x86_32.s
│   └── lnx-execve-x86_32.s
├── linux-x86_64
│   ├── lnx-execve-fast-x86_64.s
│   ├── lnx-execve-setreuid-x86_64.s
│   ├── lnx-execve-x86_64.s
│   └── lnx-write-stack-moo-x86_64.s
├── test
│   └── shellcode-exec.c
└── win_x86
    └── win-reverse-tcp-x86_32.s
```

## Development Files
In addition to the shellcodes, this repository includes several accompanying development files in /dev, most of them are written in C.

## Test Files
You can also find in the /test folder, codes for testing shellcodes in executable format.

## Notes
 * Most shellcodes are written using the Intel assembly syntax, with comments following all important instructions.
 * Linux shellcodes have been tested and debugged on 32-bit and 64-bit version of Linux Ubuntu.
 * The commands displayed in the comment section at the top of the source files are intended for assembly
   and linking on a 64-bit host. Make sure the produced ELF object files match the bitness of your linker.
 * Feel free to use the 'binary string toolkit' to dump the assembled shellcodes in binary strings. This project is available at https://github.com/e3prom/bst

## Disclaimer
 * Please make proper use of these shellcodes. They are intended for educational purposes only.
 * No canaries were harmed in the development process of the shellcodes.
