/* generic-stack-overflow-argv.c

   Generic dummy program with a stack based overflow vulnerability.

   The program get input from the command-line argument, which is ideal for
   debugging under a debugger like Immunity Debugger.

   Cross-compilation for Windows x86 (DEP and ASLR may be manually disabled):
   /usr/bin/i686-w64-mingw32-gcc-win32 -Wl,--no-nxcompat -Wl,--no-dynamicbase \
   -m32 generic-stack-overflow-argv.c -o generic-stack-overflow-argv.exe

   ** Warning: the space character (\x20) is a bad character as it terminates
   the argument string.
*/
#include <stdio.h>
#include <string.h>
void function(char **argv) {
  char char_array[500];
  strcpy(char_array, argv[1]);
  printf("%s\n", char_array);
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    function(argv);
  } else {
    printf("You need to input at least one argument.\n");
  }
  return 0;
}
