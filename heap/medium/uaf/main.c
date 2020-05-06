#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct Heap{
	void* ptr;
	int size;
};

struct Heap pheap[100];

void add() {
	int idx = 0;
	int size = 0;

	for(idx  = 0; pheap[idx].ptr != NULL; ++idx);
	if(idx == 100) {
		printf("full\n");
		return ;
	}

	printf("Size:");
	scanf("%d", &size);

	pheap[idx].size = size;
	pheap[idx].ptr = malloc(size);

	printf("Content:");

	read(0, pheap[idx].ptr, size);
	printf("OK\n");
}


void del() {
	int idx = 0;
	printf("idx: \n");
	scanf("%d", &idx);
	free(pheap[idx].ptr);
	printf("OK\n");
}

int main(void) {
	setbuf(stdin, NULL);	
	setbuf(stdout, NULL);	
	while(1) {
		int select = 0;
		printf("1.add\n2.del\n");
		scanf("%d", &select);
		if(select == 1) {
			add();
		}else if(select == 2) {
			del();
		}else {
			break;
		}
	}
	return 0;
}
