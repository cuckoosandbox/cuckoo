#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sd > 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(80);

    int ret = connect(sd, (struct sockaddr *)&addr , sizeof(addr));

    return close(sd) && ret == 0;
}
