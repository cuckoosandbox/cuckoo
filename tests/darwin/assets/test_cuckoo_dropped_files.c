#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char const *argv[])
{
	FILE *f = fopen("something.txt", "w");
	if (f == NULL) {
		return EXIT_FAILURE;
	}
	fprintf(f, "HERE YOU ARE\n");
	fclose(f);
	return EXIT_SUCCESS;
}
