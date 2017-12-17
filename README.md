# Shellcode
This repository holds a collection of shellcodes I wrote for various operating systems, architectures and instruction sets. Null bytes have been avoided whenever possible so the shellcodes could be used inside buffers or transmitted over common protocols without terminating. The shellcodes have not been optimized for their lengths, nor for their compatibility or portability. They're however interesting for educational purposes as you can more easily read them and can be used as a reference for further improvements or analysis.

## Assembly
Otherwise stated in the comments of the source files, all shellcodes can be assembled using the [NASM](http://www.nasm.us) assembler.

```
.
├── linux-x86
│   ├── lnx-execve-setreuid-x86_32.s
│   └── lnx-execve-x86_32.s
└── linux-x86_64
    ├── lnx-execve-setreuid-x86_64.s
    └── lnx-execve-x86_64.s
```

## Notes & Observations
 * Linux shellcodes have been tested and debugged on a 64-bit Ubuntu 17.10 host with ASLR and DEP enabled.

## Disclaimer
Please make proper use of these shellcodes. They are intended for educational purposes only.
