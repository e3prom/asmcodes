; lnx-write-stack-moo-x86_64.s
; Linux x86_64 shellcode that moo on standard output using the string on stack
; method. This null-free shellcode is 271 bytes long and has not been optimized
; for size, but it illustrates how you can push several long strings onto the
; stack. Note the call to exit (#60) with status code 0.
;
; Assembly instructions:
; nasm lnx-write-stack-moo-x86_64.s
BITS 64

global _start

section .text
_start:
  ; ssize_t write(int fd, const void *buf, size_t count);
  xor rax, rax                  ; Zero out RAX
  inc rax                       ; Increment RAX to 1 = write syscall
  mov rdi, rax                  ; Copy 1 to RDI (argv[1]) = stdout

  ; Push strings onto the stack.
  ; See below for converting the strings with python:
  ; python
  ; s1 = '                (__) \n'
  ; s2 = '                (oo) \n'
  ; [...]
  ; s1[::-1].encode('hex')[0:8]
  ; s1[::-1].encode('hex')[8:24]
  ; [...]
  l7:
  push 0x0a20202e               ; Push the first dword onto the stack
  mov rbx, 0x2e2e223f7961646f   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push our string onto the stack.
  push 0x74206465               ; Push remaining space characters
  mov rbx, 0x6f6f6d20756f7920
  push rbx                      ; Push RBX onto the stack
  mov rbx, 0x65766148222e2e2e   ; Copy remaining bytes for line 7
  push rbx                      ; Push RBX onto the stack

  l6:
  push 0x0a20207e               ; Push the first dword onto the stack
  mov rbx, 0x7e2020207e7e2020   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x20202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  l5:
  push 0x0a20205c               ; Push the first dword onto the stack
  mov rbx, 0x02f2d2d2d5c2f2020  ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x2a202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  l4:
  push 0x0a20207c               ; Push the first dword onto the stack
  mov rbx, 0x7c202020207c202f   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x20202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  l3:
  push 0x0a202f5c               ; Push the first dword onto the stack
  mov rbx, 0x2d2d2d2d2d2d2f20   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x20202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  l2:
  push 0x0a296f6f               ; Push the first dword onto the stack
  mov rbx, 0x2820202020202020   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x20202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  l1:
  push 0x0a295f5f               ; Push the first dword onto the stack
  mov rbx, 0x2820202020202020   ; Copy the remaining 8 bytes to RBX
  push rbx                      ; Push RBX onto the stack
  push 0x20202020               ; Push remaining space characters
  mov rbx, 0x2020202020202020
  push rbx

  mov rsi, rsp                  ; Copy stack pointer to RSI (argv[2])
  xor rdx, rdx                  ; Set RDX (argv[3]) to string's size
  add rdx, 230                  ; Our string is 230 bytes long
  syscall

  ; void _exit(int status);
  xor rax, rax                  ; Zero out RAX
  add rax, 60                   ; Set RAX to 60 = exit syscall
  xor rdi, rdi                  ; Zero out RDI (argv[1]) = 0
  syscall
