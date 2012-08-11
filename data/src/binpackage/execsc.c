#include <unistd.h>
#include <stdio.h>
#include <windows.h>

int main (int argc, char ** argv) {
	int fd;
	char buf[2048] = {0};

	if (argc < 2) return 1;

	// read in shellcode from analysis target file
	fd = open(argv[1], 0);
	read(fd, buf, 2048);
	close(fd);

	// jump into shellcode
	int (*func)();
	func = (int (*)()) buf;
	(int)(*func)();

	return 0;
}

