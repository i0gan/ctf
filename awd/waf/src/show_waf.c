#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define BINARY_PATH "./waf"
#define SAVE_PATH   "./arr"
//#define SAVE

int gen_arr(const char *binary_path) {
	int fd = open(binary_path, O_RDONLY);
	char ch;
	char buf[16];
	if(-1 == fd) {
		perror("open:");
		return -1;
	}
	
#ifdef SAVE
	int fd2 = open(SAVE_PATH,O_CREAT |O_WRONLY);		
	if(-1 == fd2) {
		perror("open:");
		return -1;
	}
#endif

	write(1, "\n[\n", 3);
	while(read(fd, &ch, 1)) {
		sprintf(buf, "\\x%02x", ch);
		write(1, buf, strlen(buf));
#ifdef SAVE
		write(fd2, buf, strlen(buf));
#endif
	}
	write(1, "\n]\n", 3);

	close(fd);
#ifdef SAVE
	close(fd2);
#endif
}

int main(void) {
	gen_arr(BINARY_PATH);
	return 0;	
}
