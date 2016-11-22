#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(int argc, char *argv[])
{
	struct passwd *pw = getpwuid(geteuid());
	assert(pw != NULL);
	if (strcmp("root", pw->pw_name) == 0) {
		printf("Hello, r00t!\n");
	} else {
		printf("Hello, user!\n");
	}

	return 0;
}
