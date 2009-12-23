#ifndef __CAPTURE_H
#define __CAPTURE_H 1

#include <pcap.h>

int capture(char *interface, char bittorrent, char edonkey);
void capture_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

#define CAPTURE_BITTORRENT 0x01
#define CAPTURE_EDONKEY 0x02

struct decoded_hash {
	char *hash;
	char address[4];
	unsigned short port;
	struct decoded_hash *next;
};

#define CREATE_DECODED_HASH(hash_name) do { \
	hash_name = (struct decoded_hash *) malloc(sizeof(struct decoded_hash)); \
	hash_name->hash = NULL; \
	bzero(hash_name->address, sizeof(char) * 4); \
	hash_name->port = 0; \
	hash_name->next = NULL; \
	} while (0)

#endif
