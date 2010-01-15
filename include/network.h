#ifndef __NETWORK_H
#define __NETWORK_H 1

int network_setup(char *hostname, unsigned short port);
int network_send(char *text);
void network_teardown(void);

#endif
