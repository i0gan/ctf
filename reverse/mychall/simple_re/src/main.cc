#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>


struct flag_data {
	char buf[65] = {0};
	int c_pos = 0;
	int length = 0;
};

const char *real_flag = "^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%%#@$^&$=!%$*$&^~&*$=#+@(^+$=@+^%~";

struct flag_data flag;
sem_t sem_1, sem_2;


void *thread_func_1(void *arg);
void *thread_func_2(void *arg);
std::string encode(const std::string &s);
bool check_flag();

void *thread_func_1(void *arg) {
	while(flag.c_pos < flag.length) {
		flag.buf[flag.c_pos] = flag.buf[flag.c_pos] ^ (flag.c_pos % 16) + 1;
		++flag.c_pos;
		sem_post(&sem_1);
		sem_wait(&sem_2);	
	}
	sem_post(&sem_1);
	flag.buf[flag.c_pos] = '\x0';
	return (void*)0;
}

void *thread_func_2(void *arg) {
	while(flag.c_pos < flag.length) {
		sem_wait(&sem_1);	
		flag.buf[flag.c_pos] = (flag.buf[flag.c_pos] ^ (flag.c_pos % 32)) + (flag.c_pos % 16);
		++flag.c_pos;
		sem_post(&sem_2);
	}
	sem_post(&sem_2);
	flag.buf[flag.c_pos] = '\x0';
	return (void*)0;
}

bool check_flag() {
	std::string flag_ = encode(flag.buf);
	//std::cout << "ok[" << flag.buf << "] re [" << flag_ << "] real_flag[" << real_flag << "]\n";
	return flag_ == real_flag;
}

std::string encode(const std::string &s) {
	static const char* code_chars = "~`!@#$%^&*()-_+={}[]:;\"'|\\<>?,./";
	int len = s.size();
	std::string res;
	res.reserve(len * 2);
	for (int i = 0; i < len; i += 1) {
		struct enc {
			unsigned char a:4;
			unsigned char b:4;
		}* encoder = (struct enc *)(s.data() + i);
		char out[2];
		out[0] = code_chars[encoder->a];
		out[1] = code_chars[encoder->b];
		res += std::string(out, sizeof(out));
	}
	return res;
}


int main(int argc, char **argv) {
	if(argc < 3) {
		std::cout << "Useage: ./simple_re [-f] [your flag]" << '\n';
		return 0;
	}

	const char *str = "f:";
	char opt = getopt(argc, argv, str);
	if(__builtin_expect(opt != 'f', 0)) {
		std::cout << "error usage\n";
		return -1;
	}

	if(sem_init(&sem_1, 0, 0) != 0) {
		perror("sem_init");
		return -1;
	}

	if(sem_init(&sem_2, 0, 0) != 0) {
		perror("sem_init");
		return -1;
	}

	// copy flag data to global flag_buf

	memcpy(flag.buf, argv[2], 64);
	flag.buf[64] = '\x00';
	flag.length = strlen(flag.buf);

	pthread_t tid_1, tid_2;
	if(pthread_create(&tid_1, nullptr, thread_func_1, nullptr) != 0) {
		perror("pthread_create");
		return -1;
	}

	if(pthread_create(&tid_2, nullptr, thread_func_2, nullptr) != 0) {
		perror("pthread_create");
		return -1;
	}

	pthread_join(tid_1, nullptr);
	pthread_join(tid_2, nullptr);

	std::cout << "Wait...\n";
	sleep(1);

	if(check_flag()) {
		std::cout << "Congratulations! You did it!\n";
	}else {
		std::cout << "No! You are wrong!\n";
	}
	return 0;
}
