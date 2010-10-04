/*
 * Hashgrabd - Utility to capture eDonkey and BitTorrent crytographic hashes from BPF.
 * 
 * Copyright (C) 2010 University of Lancaster
 * 
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version. This program is distributed in the 
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without 
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details. You should have received a copy of the GNU General 
 * Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CAPTURE_H
#define __CAPTURE_H 1

#include <pcap.h>

int capture(char *interface, unsigned char capture_options, char *file, char *filter);
void capture_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void sanitize_filename(char *filename, unsigned short length);

extern pcap_t *pcap_handle;

#define CAPTURE_BITTORRENT 0x01
#define CAPTURE_EDONKEY 0x02
#define CAPTURE_CONSOLE 0x04
#define CAPTURE_NETWORK 0x08
#define CAPTURE_EDONKEY_FILENAME 0x10
#define CAPTURE_PROMISC 0x20

struct decoded_hash {
	char *hash;
	struct decoded_hash *next;
	char *filename;
	char exchange_type;
};

#define CREATE_DECODED_HASH(hash_name) do { \
	hash_name = (struct decoded_hash *) malloc(sizeof(struct decoded_hash)); \
	hash_name->hash = NULL; \
	hash_name->filename = NULL; \
	hash_name->next = NULL; \
	hash_name->exchange_type = 'o'; \
	} while (0)

#define DESTROY_DECODED_HASH(head, itr) do { \
	for (itr = head; itr != NULL; itr = head) { \
		head = itr->next; \
		free(itr->hash); \
		if (itr->filename) { \
			free(itr->filename); \
		} \
		free(itr); \
	} \
	} while (0)

#define APPEND_DECODED_HASH(head, tail, new) do { \
	if (head == NULL) { \
		head = new; \
		tail = new; \
	} else { \
		tail->next = new; \
		tail = new; \
	} \
	} while (0)

#endif
