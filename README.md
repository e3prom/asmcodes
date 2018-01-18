# Shellcode
This repository holds a collection of shellcodes I wrote for various operating systems, architectures and CPU instruction sets. All shellcodes are null-byte free so they can be transmitted inside buffers and over common protocols without terminating. Keep in mind that Most shellcodes have not been optimized in terms of length and portability, however they are still interesting for educational purposes as you can easily parse them and understand their working. They can also be used as a reference for further improvements or for studying shellcode development.

## Shellcodes Assembly
Unless otherwise stated in the comment block of the source files, all shellcodes can be assembled using the [NASM](http://www.nasm.us) assembler.

```
├── linux-x86
│   ├── lnx-execve-callsub-x86_32.s
│   ├── lnx-execve-cdq-xchg-x86_32.s
│   ├── lnx-execve-setreuid-x86_32.s
│   └── lnx-execve-x86_32.s
├── linux-x86_64
│   ├── lnx-execve-fast-x86_64.s
│   ├── lnx-execve-setreuid-x86_64.s
│   └── lnx-execve-x86_64.s
└── win_x86
    └── win-reverse-tcp-x86_32.s
```

## Development Files
In addition to the shellcodes, the repository includes several accompanying development files, mostly written in C. Among those, exploit development examples, proof of concept codes, and more.

## Notes
 * Most shellcodes are written using the Intel syntax, with comments following all important instructions.
 * Linux shellcodes have been tested and debugged on 32-bit and 64-bit version of Linux Ubuntu.
 * The commands displayed in the comment section at the top of the source files are intended for assembly
   and linking on a 64-bit host. Make sure the produced ELF object files match the bitness of your linker.

## Disclaimer
 * Please make proper use of these shellcodes. They are intended for educational purposes only.
 * No canaries were harmed in the development process of the shellcodes.
