#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
	errno = 0;
	fopen("doesn't matter", "r");
	// errno = EINVAL = 22
	return 0;
}
