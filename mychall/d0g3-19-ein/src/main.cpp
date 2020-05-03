#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void func();
void menu();
void init();
void show();
void del();
void add();
char *plist[12];

void init() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}

void menu() {
	std::cout << "1. %#@>" << std::endl;
	std::cout << "2. !$#<" << std::endl;
	std::cout << "3. $(@^" << std::endl;
	std::cout << ">>";
}

void func() {
	int a = 0;
	int times = 0;
	while(times < 20) {
		menu();
		std::cin >> a; 
		switch(a) {
			case 1: add(); break;
			case 2: del(); break;
			case 3: show(); break;
			default: 
					exit(0);
		}
		++times;
	}
}

void add() {
	size_t size;
	int idx;
	std::cout << "???" << std::endl;
	std::cin >> size;
	for(idx = 0; idx <= 12; ++idx) {
		if(plist[idx] == nullptr) {
			break;
		}
		if(idx == 12) {
			std::cout << "!!!" << std::endl;
			return;
		}
	}

	if(size <= 0 || size >= 0x100) {
		std::cout << "!#@$%" << std::endl;
		return;
	}

	plist[idx] = new char[size];
	std::cout << ":>";
	size_t i = 0;
	for(i = 0; i < size; ++i) {
		read(0, plist[idx] + i, 1);
		if(*(plist[idx] + i) == '\n')
			break;
	}
	*(plist[idx] + i) = '\x00';
}

void del() {
	int idx;
	std::cout << "???" << std::endl;
	std::cin >> idx;
	if(idx < 0 || idx >= 12) return;

	if(plist[idx] == nullptr) {
		std::cout << "!!!" << std::endl;
		return ;
	}

	delete[] plist[idx];
	plist[idx] = nullptr;
}

void show() {
	int idx;	
	std::cout << "???" << std::endl;
	std::cin >> idx;
	if(idx < 0 || idx >= 12) return ;
	if(plist[idx] == nullptr) {
		std::cout << "!!!" << std::endl;
		return ;
	}
	std::cout << "$->" << plist[idx] << std::endl;
}

int main(int, char**) {
		init();
std::cout <<" ____   ___   ____ _____       _  ___        _____ ___ _   _  \n"     <<
			"|  _ \\ / _ \\ / ___|___ /      / |/ _ \\      | ____|_ _| \\ | |\n" <<
			"| | | | | | | |  _  |_ \\ _____| | (_) |_____|  _|  | ||  \\| |\n"   <<
			"| |_| | |_| | |_| |___) |_____| |\\__, |_____| |___ | || |\\  |\n"   <<
			"|____/ \\___/ \\____|____/      |_|  /_/      |_____|___|_| \\_|\n";
	func();
	return 0;
}
