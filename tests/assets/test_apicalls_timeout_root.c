#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	system("whoami");
	sleep(10);
	system("whoami");
    return 0;
}
