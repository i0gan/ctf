TARGET = pwn
CFLAGS = -fstack-protector-all -fPIC -std=c++11
OBJ = main.o
RM = rm -f
CC = g++

$(TARGET) : $(OBJ)
	$(CC) -o $@ $< $(CFLAGS)
$(OBJ) :%.o:%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	$(RM) $(OBJ) $(TARGET)

