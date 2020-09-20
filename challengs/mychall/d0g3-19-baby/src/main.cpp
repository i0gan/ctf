#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

void func();
void init();
void del();
void add();

std::vector<char *> addrs;

void init() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	addrs.resize(14, nullptr);
}

void func() {
	int a = 0;
	int times = 0;
	while(times < 20) {
		std::cout << "^_^:" << std::endl;
		std::cin >> a; 
		switch(a) {
			case 1: add(); break;
			case 2: del(); break;
			default: 
			exit(0);
		}
		++times;
	}
}

void add() {
	size_t size;

	int idx = 0;
	std::cout << "?_?" << std::endl;
	for(std::vector<char *>::iterator iter = addrs.begin(); iter != addrs.end(); ++iter) {
                if(*iter == nullptr) {
			break;	
		}
		++ idx;	
	}

	if(idx >= 12) {
			std::cout << "!_!" << std::endl;
			return;
	}

	std::cin >> size;
	if(size <= 0 || size >= 0x100) {
		std::cout << ":)" << std::endl;
		return;
	}

	addrs[idx] = new char[size];
	std::cout << ":>";

	read(0, addrs[idx], 0x80);
}

void del() {
	int idx;
	std::cout << "~_~" << std::endl;
	std::cin >> idx;
	if(idx < 0 || idx >= 12) return;

	if(addrs[idx] == nullptr) {
		std::cout << "!_!" << std::endl;
		return ;
	}

	delete[] addrs[idx];
	addrs[idx] = nullptr;
}


int main(int, char**) {
	init();

std::cout <<

"     _  ___        _____       _           _\n"         
"  __| |/ _ \\  __ _|___ /      | |__   __ _| |__  _   _ \n"
" / _` | | | |/ _` | |_ \\ _____| '_ \\ / _` | '_ \\| | | |\n"
"| (_| | |_| | (_| |___) |_____| |_) | (_| | |_) | |_| |\n"
" \\__,_|\\___/ \\__, |____/      |_.__/ \\__,_|_.__/ \\__, |\n"
"             |___/                               |___/ \n";

	func();
	return 0;
}
