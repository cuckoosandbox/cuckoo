#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char *argv[])
{
	printf("parent's here\n");

	pid_t child = fork();
	assert(child >= 0);

	if (child == 0) {
		// child
		printf("child's here\n");
	} else {
		// parent
		int status;
		wait(&status);
	}


	return 0;
}
