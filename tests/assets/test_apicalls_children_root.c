#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>


void grandchild(void)
{
	printf("grandchild started\n");
	int a = atoi("1337");
	a = atoi("1341");
	a = atoi("6243");
	a = atoi("21");
	a = atoi("1337");
	a = atoi("1341");
	a = atoi("6243");
	a = atoi("21");
	sleep(1);
	a = atoi("87162");
	a = atoi("1337");
	a = atoi("1341");
	a = atoi("6243");
	a = atoi("21");
	a = atoi("87162");
	a = atoi("87162");
	fprintf(stdout, "grandchild done\n");
}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		grandchild();
		return 0;
	}
	printf("parent started\n");

	pid_t child = fork();
	assert(child >= 0);

	if (child == 0) {
		printf("child started\n");
		char *const new_args[] = {argv[0], "yep", NULL};
		execve(new_args[0], (char *const *)&new_args, NULL);
		fprintf(stderr, "CHILD FAILED\n");
	} else {
		int status;
		wait(&status);
		printf("parent done\n");
	}

	return 0;
}
