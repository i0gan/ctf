TARGET = pwn1
CFLAGS = -m32 -no-pie -fno-stack-protector
OBJ = main.o
RM = rm -f
CC = gcc

$(TARGET) : $(OBJ)
	$(CC) -o $@ $< $(CFLAGS)
$(OBJ) :%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	$(RM) $(OBJ) $(TARGET)

