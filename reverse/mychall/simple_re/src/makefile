CC     := g++
TARGET := simple_re_
OBJ    := main.o
FLAGS  := --static -lpthread -W

$(TARGET):$(OBJ)
	$(CC) $^ -o $(TARGET) $(FLAGS)

$(OBJ):%.o:%.cc
	$(CC) -c $^ -o $@

clean:
	$(RM) $(OBJ) $(TARGET)
