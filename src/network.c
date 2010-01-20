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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <unistd.h>

int network_fd = 0;
struct addrinfo *network_destination = NULL, *head;

int network_setup(char *hostname, unsigned short port) {
	struct addrinfo hints, *servinfo, *itr;
	char port_as_characters[6];
	int rv;

	/* Convert back to a string because getaddrinfo takes a string... yes... I know.. */
	snprintf(port_as_characters, 6, "%i", port);

	/* Set up hints on what data we require. */
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	/* Get the address info for this server if we can. */
	if ((rv = getaddrinfo(hostname, port_as_characters, &hints, &servinfo)) != 0) {
		warnx("could not create socket information: %s", gai_strerror(rv));
		return -1;
	}

	/* Store the head address node so it can be free'd later. */
	head = servinfo;

	/* Loop through results attempting to make a socket. In theory this should make this IPv6 compatable? */
	for (itr = servinfo; itr != NULL; itr = itr->ai_next) {
		if ((network_fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol)) == -1) {
			continue;
		}

		break;
	}

	/* Did we bind correctly? */
	if (itr == NULL) {
		warnx("could not bind to socket");
		return -1;
	}

	/* Store this for the future. */
	network_destination = itr;

	/* So far so good. */
	return 0;
}

int network_send(char *text) {
	int numbytes;

	/* We can't send if we don't have a socket. */
	if (network_fd == 0 || network_destination == NULL) {
		return -1;
	}

	if ((numbytes = sendto(network_fd, text, strlen(text), 0, network_destination->ai_addr, network_destination->ai_addrlen)) == -1) {
		return -1;
	}

	return 0;
}

void network_teardown(void) {
	close(network_fd);
	freeaddrinfo(head);
}
