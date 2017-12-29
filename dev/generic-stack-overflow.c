/* generic-stack-overflow.c

   Generic dummy program with a stack based overflow vulnerability.
   Using the deprecated 'gets()' std libc function (gcc warnings could be ignored).

   Compile (32bit):
   cc -m32 -fno-stack-protector generic-stack-overflow.c -o generic-stack-overflow

   Overflow & EIP Control (32-bit):
   ./generic-stack-overflow < <(python -c 'print "A" * (112) + "R" * 4')

   Compile (64bit):
   cc -fno-stack-protector generic-stack-overflow.c -o generic-stack-overflow

   Overflow & RIP Control (64-bit):
   ./generic-stack-overflow < <(python -c 'print "A" * (128-8) + "R" * 8')
*/
#include <stdio.h>
void function(void) {
  char array[100];

  gets(array);
  printf("%s\n", array);
}

int main() {
  function();
  return 0;
}
