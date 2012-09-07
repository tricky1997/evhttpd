#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char buf[1024];

int main(void)
{
	int sfd;
	int connfd;
	int n;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if ( -1 == bind(sfd, (const struct sockaddr *)&addr, sizeof(addr))) {
		printf("BIND!\n");
		abort();
	}
	listen(sfd, 2);
	connfd = accept(sfd, NULL, NULL);
	while ((n = read(connfd, buf, sizeof(buf)))) {
		if ( n == -1) {
			printf("READ!\n");
			break;
		}
		write(STDOUT_FILENO, buf, n);
	}
	close(sfd);
	close(connfd);
	exit(0);
}
