.c.o:
	gcc -g -c $?

text:text.o
	gcc -g -o text text.o   -lpcap


