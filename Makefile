CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic -std=c11

OBJS=des.o

all: main.c $(OBJS)
	$(CC) $(CFLAGS) -o des-example main.c $(OBJS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

