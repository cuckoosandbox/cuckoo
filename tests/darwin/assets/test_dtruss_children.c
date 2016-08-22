#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char *argv[])
{
	write(1, "Hello, I'm parent!", 18);

	pid_t child = fork();
	assert(child >= 0);

	if (child == 0) {
		// child
		write(1, "Hello from child!", 17);
	} else {
		// parent
		printf("Hello again from the parent! My child is %d\n", child);
		int status;
		wait(&status);
	}


	return 0;
}
