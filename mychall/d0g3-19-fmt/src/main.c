#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
	mprotect((void*)0x08049000, 0x2000, PROT_READ | PROT_WRITE);
}
void exploit_me(char *buf) {
	puts(buf);
	system("echo your name is ku");
}

int main(void) {
    init();
	static times = 0;
    char buf[400] = "hello: ";

    printf("Welcome to D0g3-19-simple-fmt\nwhat's your name?");

    fgets((char *)buf + 7, 100, stdin);

	if(times != 0) {
		exploit_me(buf);
	}

    printf(buf);
	++ times;
    return 0;
}
