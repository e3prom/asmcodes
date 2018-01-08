# Shellcode
This repository holds a collection of shellcodes I wrote for various operating systems, architectures and CPU instruction sets. Null bytes have been avoided whenever possible so the shellcodes could be used inside buffers and transmitted over common protocols without terminating. The shellcodes have not been optimized for their lengths, nor for their compatibility or portability. They're however interesting for educational purposes as you can easily parse them and can be used as a reference for further improvements and for studying shellcode development.

## Shellcodes Assembly
Otherwise stated in the comments of the source files, all shellcodes can be assembled using the [NASM](http://www.nasm.us) assembler.

```
├── linux-x86
│   ├── lnx-execve-callsub-x86_32.s
│   ├── lnx-execve-cdq-xchg-x86_32.s
│   ├── lnx-execve-setreuid-x86_32.s
│   └── lnx-execve-x86_32.s
├── linux-x86_64
│   ├── lnx-execve-setreuid-x86_64.s
│   └── lnx-execve-x86_64.s
└── README.md
```

## Development Files
In addition to the shellcodes, the repository also includes several accompanying development files, mostly written in C. Among those, exploit development examples, proof of concept codes, and more.

## Notes
 * Most shellcodes are written using the Intel syntax, with comments following all important instructions.
 * Linux shellcodes have been tested and debugged on 32-bit and 64-bit version of Linux Ubuntu.
 * The commands displayed in the comment section at the top of the source files are intended for assembly
   and linking on a 64-bit host. Make sure the produced ELF object files match the bitness of your linker.

## Disclaimer
Please make proper use of these shellcodes. They are intended for educational purposes only.
