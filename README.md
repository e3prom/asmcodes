# Shellcode
This repository holds a collection of shellcodes I wrote for various operating systems, architectures and instruction sets. Null bytes have been removed whenever possible so the shellcode can be used inside of buffers or over common protocols without breaking. They've not been optimized for size, therefore they genenate lengthy machine codes. They're however interesting for educational purpose as you can easily decode them and can be used as a reference for further improvements (e,g. reducing machine code size, omiting bad characters and/or avoiding detection).

## Assembly
These shellcodes can be assembled using NASM. Linux shellcodes have been tested and debugged on a 64-bits Ubuntu 17.10 (4.13.0-17-generic).

## Disclaimer
Please make proper use of these shellcodes. They are intended for education purposes only.
