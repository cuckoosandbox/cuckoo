#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	write(1, "Hello, world!\n", 0xE);
	sleep(5);
	write(1, "Hello, world!\n", 0xE);
}
