CC=gcc
CFLAGS=-Wall -g
INCLUDE=-I. -I./util

.PHONY: build clean

build: aws

aws: ./server.o ./util/lin/sock_util.o ./util/http-parser/http_parser.o
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^ -laio

./server.o: ./server.c

./util/lin/sock_util.o: ./util/lin/sock_util.c ./util/lin/sock_util.h ./util/debug.h ./util/util.h

./util/http-parser/http_parser.o: ./util/http-parser/http_parser.c ./util/http-parser/http_parser.h
	make -C ./util/http-parser http_parser.o

clean:
	make -C ./util/http-parser/ clean
	rm -rf ./util/*.o ./*.o ./util/lin/*.o aws