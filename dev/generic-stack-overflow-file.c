/* generic-stack-overflow-file.c

   Generic dummy program with a stack based overflow vulnerability.
   Written by e3prom (github.com/e3prom)

   Exploit code available at: 
   https://gist.github.com/e3prom/593ef5f05792663ee8cb1caf4e121d69

   This program get input from a file; read it and store the content to the
   stack memory using the C library function fread().

   The purpose of this program is to:
    - Demonstrate how some functions could be unsafe when used improperly.
    - Demonstrate a stack-based buffer overflow.
    - Demonstrate the importance of DEP (NX/XD) support at compile-time.

   This program can be exploited on Windows by overwriting the SE handler
   pointer in the non-SafeSEH chain.

   Cross-compilation for Windows x86 (DEP and ASLR may be manually disabled):
   /usr/bin/i686-w64-mingw32-gcc-win32 -Wl,--no-nxcompat -Wl,--no-dynamicbase \
   -m32 generic-stack-overflow-file.c -o generic-stack-overflow-file.exe
*/
#include <stdio.h>
#include <string.h>
void function(char **argv) {
  char char_array[500];
  size_t size = 0;
  FILE *fp = fopen(argv[1], "r");

  if (fp) {
    fseek(fp, 0, SEEK_END);		// seek the entire file.
    size = ftell(fp);			// set size at the current read position.
    rewind(fp);				// rewind to the beggining of file.
    fread(char_array, size, 1, fp);	// read from file.
    char_array[size] = '\0';		// null-terminate the buffer.
    fclose(fp);
    printf("%s\n", char_array);
  } else {
    printf("Error: file \"%s\" cannot be read.\n", argv[1]);
  }
}

int main(int argc, char *argv[]) {
  if (argc > 1) {
    function(argv);
  } else {
    printf("You must specify a file as the first argument.\n");
  }
  return 0;
}
