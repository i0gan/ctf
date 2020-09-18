/*
 * orignal author: yangshuangfu
 * github link: https://github.com/yangshuangfu/PwnWAF
 * modified author: i0gan
 * github link: https://github.com/i0gan/pwn/env/awd/waf.c
 * modified time  : 2020-09-18
 */

// complie:
// gcc waf.c -o waf
// before you use it, you should backup your binary file, then rename waf as binary name

#include<stdlib.h>
#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<error.h>
#include<sys/wait.h>
#include<sys/ptrace.h>
#include<sys/syscall.h>
#include<sys/user.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<string.h>

#define FILENAME "./pwn"
#define LOGNAME "./log"
#define MACHINE 64

#define NEW_CONNECT_SHOW_STR "\n************** new attack *************\n"
#define READ_SHOW_STR        "\nread:\n"
#define WRITE_SHOW_STR       "\nwrite:\n"

enum SYSTYPE {
	READ,
	WRITE
};

int state = -1;

int check_standard(int fd){
	return fd == 1 || fd == 0;
}

void write_log(pid_t pid, char* addr, int size, enum SYSTYPE flag){

	int fd = open(LOGNAME, O_CREAT|O_APPEND|O_WRONLY, 0666);
	int i = 0,j = 0;
	char data;
	char* buf = (char*)malloc(size + 1);

	for(i = 0; i < size; i++){
		data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
		buf[i] = data;
	}

	// 判断是否状态是否发生变化,发生变化就写入不同的状态
	if(state != flag)	{
		if(flag == READ)
			write(fd, READ_SHOW_STR, sizeof(READ_SHOW_STR));
		else
			write(fd, WRITE_SHOW_STR, sizeof(WRITE_SHOW_STR));
		state = flag;
	}

	write(fd, buf, size);
	close(fd);
	free(buf);
}


void write_new_attack() {
	// 分割每次攻打的符号
	int fd = open(LOGNAME, O_CREAT|O_APPEND|O_WRONLY, 0666);
	write(fd, NEW_CONNECT_SHOW_STR, sizeof(NEW_CONNECT_SHOW_STR));
	close(fd);
}

int main(int argc, char* argv[]){
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	pid_t pid;
	struct user_regs_struct regs;
	int status;
	int insyscall = 0;
	int first_time = 1;
	pid = fork();
	int sys_num;
	enum SYSTYPE sys_status;
	// we use child process to exec 
	if(pid == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		argv[1] = FILENAME;
		status = execvp(FILENAME, argv+1);
		if(status<0){
			perror("ERROR EXEC\n");
			return -1;
		}
	}
	// parent to get child syscall
	else if (pid > 0){
		write_new_attack();
		while(1){
			wait(&status);
			if(WIFEXITED(status))
				break;
			// get rax to ensure witch syscall
			ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#if MACHINE == 64
			sys_num = regs.orig_rax;
#elif MACHINE == 32
			sys_num = regs.orig_eax;
#endif
			if (sys_num != SYS_read && sys_num != SYS_write){
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				continue;
			}
			if (insyscall==0){
				insyscall = 1;
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
			}
			else{
				// we should ignor the first time
				// checl it is standard pipe or not
				int is_standard = 0;
#if MACHINE == 64
				is_standard = check_standard(regs.rdi);
#elif MACHINE == 32
				is_standard = check_standard(regs.ebx);
#endif 
				if(!is_standard){
					first_time = 0;
					ptrace(PTRACE_SYSCALL, pid, NULL ,NULL);
					insyscall ^= 1;
					continue;
				}
				if(sys_num == SYS_read)
					sys_status = READ;
				else if (sys_num == SYS_write)
					sys_status = WRITE;
				int size = 0;
				char* addr = NULL;
#if MACHINE == 64
				size = regs.rdx;
				// size = (size + sizeof(long)-1)/sizeof(long) * sizeof(long) +1;
				addr = (char*)regs.rsi;
				// printf(" the addr is %lx with size %lx", addr, size);
#elif MACHINE == 32
				size = regs.edx;
				addr = (char*)regs.ecx;

#endif 
				write_log(pid, addr, size, sys_status);
				insyscall = 0;
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			}
		}
		return 0;
	}
	else{
		perror("ERROR FORK!\n");
		return -1;
	}
}
