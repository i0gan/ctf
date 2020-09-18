/*
 * orignal author: yangshuangfu
 * github link: https://github.com/yangshuangfu/PwnWAF
 * modified author: i0gan
 * github link: https://github.com/i0gan/pwn/env/awd/waf/
 * modified time  : 2020-09-18
 */

// waf for pwn awd
// complie:
// gcc waf.c -o pwn
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

#define ELF_PATH "./elf" // trace elf path
#define LOG_PATH "./log" // path to log
#define ARCH 64          // 64 or 32

//
#define NEW_ATTACK_SHOW_STR  "\n\n************************* new attack ***************************\n\n"
#define READ_SHOW_STR        "\n-------------------- read ------------------\n"
#define WRITE_SHOW_STR       "\n-------------------- write -----------------\n"
#define DANGEROUS_SHOW_STR   "\n!!!!!!!!!!!!! dangerous syscall !!!!!!!!!!!!\n"

enum sys_type {
	READ,
	WRITE
};

// error code avoid zombie parent process
#define ERROR_EXIT(x)  \
	x == 0xb7f
	
// judge is standard io
#define STANDARD_IO(x) \
	x == 0 ||          \
	x == 1

// dangerous syscall
#define TRACE_SYSCALL(x)  \
	x == __NR_rt_sigaction   || \
	x == __NR_rt_sigprocmask || \
	x == __NR_clone  || \
	x == __NR_execve


int state = -1;
int is_cut = 1;

void write_log(const char *str) {
	int fd = open(LOG_PATH, O_CREAT|O_APPEND|O_WRONLY, 0666);
	write(fd, str, strlen(str));
	close(fd);
}

void interactive_log(pid_t pid, char* addr, int size, enum sys_type type){

	int fd = open(LOG_PATH, O_CREAT|O_APPEND|O_WRONLY, 0666);
	int i = 0,j = 0;
	char data;
	char* buf = (char*)malloc(size + 1);

	for(i = 0; i < size; i++){
		data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
		buf[i] = data;
	}

	if(state != type) {
		if(type == READ)
			write(fd, READ_SHOW_STR, sizeof(READ_SHOW_STR) - 1);
		else
			write(fd, WRITE_SHOW_STR, sizeof(WRITE_SHOW_STR) - 1);
		state = type;
		is_cut = 1;
	}

	write(fd, buf, size);
	close(fd);
	free(buf);
	is_cut = 0;
}


int main(int argc, char* argv[]){
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	pid_t pid;
	struct user_regs_struct regs;
	int status;
	int is_in_syscall = 0;
	int first_time = 1;
	int dangerous_syscall_times = 0;
	pid = fork();
	int sys_num;
	enum sys_type sys_status;

	// we use child process to exec 
	if(pid == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		argv[1] = ELF_PATH;
		status = execvp(ELF_PATH, argv+1);
		if(status<0){
			perror("ERROR EXEC\n");
			return -1;
		}
	}
	// parent to get child syscall
	else if (pid > 0){
		write_log(NEW_ATTACK_SHOW_STR);

		while(1) {
			wait(&status);
			if(WIFEXITED(status) || ERROR_EXIT(status))
				break;
			// get rax to ensure witch syscall
			ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#if ARCH == 64
			sys_num = regs.orig_rax;
#elif ARCH == 32
			sys_num = regs.orig_eax;
#endif

			//printf("syscall %d\n", sys_num);
			if(TRACE_SYSCALL(sys_num)) {
				dangerous_syscall_times += 1;
				if(dangerous_syscall_times > 1)
					write_log(DANGEROUS_SHOW_STR);
			}

			if (sys_num != SYS_read && sys_num != SYS_write) {
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				continue;
			}

			if (is_in_syscall == 0) {
				is_in_syscall = 1;
				ptrace(PTRACE_SYSCALL, pid, 0, 0);
			} else {
				// we should ignor the first time
				// checl it is standard pipe or not
				int is_standard_io = 0;
#if ARCH == 64
				is_standard_io = STANDARD_IO(regs.rdi);
#elif ARCH == 32
				is_standard_io = STANDARD_IO(regs.ebx);
#endif 
				if(!is_standard_io) {
					first_time = 0;
					ptrace(PTRACE_SYSCALL, pid, NULL ,NULL);
					is_in_syscall ^= 1;
					continue;
				}

				if(sys_num == SYS_read)
					sys_status = READ;
				else if (sys_num == SYS_write)
					sys_status = WRITE;

				int size = 0;
				char* addr = NULL;
#if ARCH == 64
				size = regs.rdx;
				addr = (char*)regs.rsi;
#elif ARCH == 32
				size = regs.edx;
				addr = (char*)regs.ecx;
#endif 

				interactive_log(pid, addr, size, sys_status);
				is_in_syscall = 0;
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
			}
		}
		return status;
	}
	else{
		perror("ERROR FORK!\n");
		return -1;
	}
}
