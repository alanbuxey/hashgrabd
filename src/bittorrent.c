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

#include <strings.h>
#include <stdlib.h>

#include "capture.h"

struct decoded_hash *bittorrent_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump) {
	char protocol_ident[20], *hash;
	unsigned char protocol_length;
	unsigned short ptr = 0;
	struct decoded_hash *output;

	/* Announcements we capture are only TCP, reject UDP. */
	if (protocol == 0x11) {
		return NULL;
	}

	/* Can we read the first byte which should be 19 for BT. */
	if (length < 1) {
		return NULL;
	}

	protocol_length = buffer[ptr];
	ptr += sizeof(char);

	/* Do we have 19 bytes of ID, and if we do is there room in the buffer? */
	if (protocol_length != 19 || length < (ptr + protocol_length)) {
		return NULL;
	}

	/* Copy out the protocol identification. */
	bcopy(&buffer[ptr], &protocol_ident, protocol_length);
	protocol_ident[protocol_length] = '\0';
	ptr += protocol_length;

	/* Compare to see if we do have a BitTorrent packet. */
	if (strncasecmp("BitTorrent protocol", protocol_ident, protocol_length) != 0) {
		return NULL;
	}

	/* If we're dumping this is a bit torrent packet so dump away. */
	*dump = 1;

	/* We now do, skip reserved 8 bytes. */
	ptr += 8;

	/* Allocate memory for hash. */
	hash = (char *) malloc(sizeof(char) * 41);

	/* Copy hash into memory. */
	snprintf(hash, 41, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", buffer[ptr], buffer[ptr+1], buffer[ptr+2], buffer[ptr+3], buffer[ptr+4], buffer[ptr+5], buffer[ptr+6], buffer[ptr+7], buffer[ptr+8], buffer[ptr+9], buffer[ptr+10], buffer[ptr+11], buffer[ptr+12], buffer[ptr+13], buffer[ptr+14], buffer[ptr+15], buffer[ptr+16], buffer[ptr+17], buffer[ptr+18], buffer[ptr+19]);
	ptr += 20;
	
	/* Create output object. */
	CREATE_DECODED_HASH(output);
	output->hash = hash;

	/* Return hash. */
	return output;
} 
