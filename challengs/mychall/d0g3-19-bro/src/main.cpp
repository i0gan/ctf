#include <memory>
#include <cstdio>
#include <iostream>
#include <pthread.h>
#include <cstdlib>
#include <iterator>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct ptrList_s{
	char* ptr = nullptr;		
	size_t size = 0;
};

void func();
void menu();
void init();
void show();
void del();
void add();
void openFile();
void modify();
bool checkFileName(std::string fileName);

bool isOpenFile = false;
int fd = -1;


ptrList_s plist[10];

void init() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}
void menu() {
	std::cout << "1. add" << std::endl;
	std::cout << "2. del" << std::endl;
	std::cout << "3. modify" << std::endl;
	std::cout << "4. openEyes" << std::endl;
	std::cout << "5. show" << std::endl;
	std::cout << "6. exit" << std::endl;
	std::cout << ">>";
}

void func() {
	int a = 0;
	int times = 0;
	while(times < 30) {
		menu();
		std::cin >> a; 
		switch(a) {
			case 1: add(); break;
			case 2: del(); break;
			case 3: modify(); break;
			case 4: openFile(); break;
			case 5: show(); break;
			default: 
					exit(0);
		}
		++times;
	}
}

void add() {
	size_t size;
	int idx;
	std::cout << "How many words do you wanna say?" << std::endl;
	std::cin >> size;
	for(idx = 0; idx < 10; ++idx) {
		if(plist[idx].ptr == nullptr) {
			break;
		}
		if(idx == 9) {
			std::cout << "Poor guy,It's full!" << std::endl;
			return;
		}
	}

	if(size <= 0 || size >= 0x100) {
		std::cout << "Oh poor guy!" << std::endl;
		return;
	}

	plist[idx].ptr = new char[size];
	plist[idx].size = size;
	std::cout << "OK! Your index is: " << idx << std::endl;
}

void del() {
	int idx;
	std::cout << "What index it is?" << std::endl;
	std::cin >> idx;
	if(idx < 0 || idx >= 10) return;

	if(plist[idx].ptr == nullptr || plist[idx].size == 0) {
		std::cout << "Oh poor guy!" << std::endl;
		return ;
	}

	delete[] plist[idx].ptr;
	plist[idx].ptr = nullptr;
	plist[idx].size = 0;

}
void modify() {
	int idx;	
	std::cout << "What index it is?" << std::endl;
	std::cin >> idx;
	if(idx < 0 || idx >= 10) return ;
	if(plist[idx].ptr == nullptr || plist[idx].size == 0) {
		std::cout << "Oh poor guy!" << std::endl;
		return ;
	}

	std::cout << "What you wanna say?" << std::endl;
	for(size_t i = 0; i <= plist[idx].size; ++i) {
		read(0, plist[idx].ptr + i, 1);
	}
	std::cout << "OK!" << std::endl;
}

void openFile() {
	std::string fileName;
	std::cout << "What's file do you wanna open?" << std::endl;
	std::cin >> fileName;
	bool result = checkFileName(fileName);
	if(result == false) {
		std::cout << "Oh! shit this file can't open!" << std::endl;
		return ;
	}

	::fd = open(fileName.c_str(), O_RDONLY);

	if(fd == -1) {
		std::cout << "Oh! shit this file can't open!" << std::endl;
	}
}

bool checkFileName(std::string fileName) {
	for(std::string::iterator iter = fileName.begin(); iter != fileName.end(); ++iter) {
		if(*iter == 'g' || *iter == '*') {
			return false;
		}
	}
	return true;
}

void show() {
	int opt = 0;
	char buf[1024] = {0};
	std::cout << "1. show my input" << std::endl;
	std::cout << "2. show file text" << std::endl;
	std::cin >> opt;
	if(opt == 1) {
		int idx;	
		std::cout << "What index it is?" << std::endl;
		std::cin >> idx;
		if(idx < 0 || idx >= 10) return ;
		if(plist[idx].ptr == nullptr || plist[idx].size == 0) {
			std::cout << "Oh poor guy!" << std::endl;
			return ;
		}
		std::cout << "your text:" << std::endl;
		write(1, plist[idx].ptr, plist[idx].size);
	}else if(opt == 2) {
		if(fd == -1) {
			std::cout << "Not open file yet." << std::endl;
			return;
		}	

		std::cout << "your text:" << std::endl;
		read(fd, buf, 1024);
		write(1, buf, 1024);
	}
}

int main(int, char**) {
		init();
		std::cout << "Welcome to this!!" << std::endl;

std::cout << " ____   ___        _____       _  ___        _\n"
		  << "|  _ \\ / _ \\  __ _|___ /      / |/ _ \\      | |__  _ __ ___\n" 
		  << "| | | | | | |/ _` | |_ \\ _____| | (_) |_____| '_ \\| '__/ _ \\\n"
		  << "| |_| | |_| | (_| |___) |_____| |\\__, |_____| |_) | | | (_) |\n"
		  << "|____/ \\___/ \\__, |____/      |_|  /_/      |_.__/|_|  \\___/ \n";
		func();
		return 0;
	}
