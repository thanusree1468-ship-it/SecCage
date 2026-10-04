CC = gcc

CFLAGS = -Wall -Wextra -I./src

LIBS = -lseccomp

TARGET = seccage

SOURCES = \
	src/main.c \
	src/sandbox.c \
	src/policy.c \
	src/logger.c

OBJECTS = $(SOURCES:.c=.o)


all: $(TARGET)


$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LIBS)


src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -f $(OBJECTS) $(TARGET)


test-basic:
	./$(TARGET) --policy policies/basic.conf ./tests/safe_program


test-restricted:
	./$(TARGET) --policy policies/basic.conf ./tests/restricted_test


test-strict:
	./$(TARGET) --policy policies/strict.conf ./tests/safe_program


test-strict-block:
	./$(TARGET) --policy policies/strict.conf ./tests/restricted_test


.PHONY: all clean test-basic test-restricted test-strict test-strict-block
