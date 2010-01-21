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
#include "edonkey_internal.h"

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump) {
	unsigned char edonkey_id, edonkey_opcode, packets = 0;
	unsigned short ptr = 0;	
	unsigned int edonkey_length;
	struct decoded_hash *head = NULL, *tail = NULL, *tmp = NULL;
	struct eanimal *lookup = NULL;


        /* Announcements we capture are only TCP, reject UDP. */
        if (protocol == 0x11) {
                return NULL;
        }

	/* Can we read the first byte which should be e3 for eDonkey, do this outside of the loop first. */
	if (length < 1) {
		return NULL;
	}

	/* An eDonkey packet can contain many messages. We need to iterate throguh the entire packet to find them. */
	while (ptr <= length) {
		/* Check the start of this subsection is eDonkey. */
		edonkey_id = buffer[ptr];
		ptr += sizeof(char);
		
		/* Return the head of the LL if the packet does not begin with e3 (eDonkey) or c6 (eMule Extensions). */
		if (edonkey_id != 0xe3 && edonkey_id != 0xc5) {
			return head;
		}

		/* If we're TCP then we have an appropriate size, if not UDP doesn't have this value. */
		if (protocol == 0x06) {
			/* Is there enough room to read a packet length? */
			if (length < (ptr + sizeof(unsigned int))) {
				return head;
			}

			/* There is, copy it. NOTE: the length is already in little endian. */
			bcopy(&buffer[ptr], &edonkey_length, sizeof(unsigned int));
			ptr += sizeof(unsigned int);

#ifdef __BIG_ENDIAN__
			/* If we're on Big Endian, i.e. Sparc, convert to native endian. */
			length = ((length & 0xff) << 24) + ((length & 0xff00) << 8) + ((length & 0xff0000) >> 8) + ((length >> 24) & 0xff);
#endif

			/* Seem to need to remove a one due to opcode being counted. */
			edonkey_length--;
		} else {
			/* Assuming UDP packets, we don't get the edonkey length from the packet, so we must assume from the udp payload length. */
			edonkey_length = length - 2;
		}

		/* Sanity check. */
		if (edonkey_length < 1) {
			return head;
		}

                /* Is there enough data left in this packet to continue? If not we can't continue. */
                if (length < (ptr + edonkey_length)) {
                        return head;
                }

		/* Grab the eDonkey opcode. */
		edonkey_opcode = buffer[ptr];
		ptr += sizeof(char);

		/* Get eAnimal entry from look up tables. */
		if (edonkey_id == 0xe3) {
			if (protocol == 0x06) {
				lookup = &edonkey_tcp_table[edonkey_opcode];
			} else {
				lookup = &edonkey_udp_table[edonkey_opcode];
			}	
		} else if (edonkey_id == 0xc5) {
			if (protocol == 0x06) {
				lookup = &emule_tcp_table[edonkey_opcode];
			} else {
				lookup = &emule_udp_table[edonkey_opcode];
			}
		}

		/* If we have a function pointer for this opcode, execute it. */
		if (lookup->pointer) {
			*dump = 1;
			tmp = lookup->pointer(&buffer[ptr], edonkey_length, edonkey_opcode, protocol, dump);
			APPEND_DECODED_HASH(head, tail, tmp);
		}

		/* More the ptr along. */
		ptr += edonkey_length;

		/* Increase debug packet counter. */
		packets++;
	}

	return head;
} 

struct decoded_hash *edonkey_tcp_0x58(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump) {
	char *hash = NULL;
	unsigned short ptr = 0;
	struct decoded_hash *output = NULL;

	/* Sanity Check */
	if (length < 16) {
		return NULL;
	}

	/* Allocate memory for and extra hash. */
	hash = (char *) malloc(sizeof(char) * 33);
	snprintf(hash, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", buffer[ptr], buffer[ptr+1], buffer[ptr+2], buffer[ptr+3], buffer[ptr+4], buffer[ptr+5], buffer[ptr+6], buffer[ptr+7], buffer[ptr+8], buffer[ptr+9], buffer[ptr+10], buffer[ptr+11], buffer[ptr+12], buffer[ptr+13], buffer[ptr+14], buffer[ptr+15]);

	/* Create output object. */
	CREATE_DECODED_HASH(output);
	output->hash = hash;
	output->exchange_type = 'r';

	/* Return hash. */
	return output;
}

struct decoded_hash *edonkey_tcp_0x59(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump) {
        struct decoded_hash *output = NULL, *itr = NULL;
	unsigned short filename_length;
	char *filename = NULL;

	/* First bit is the same as the 0x58 opcode. */
        output = edonkey_tcp_0x58(buffer, length, opcode, protocol, dump);

	/* If above call failed, return now. */
	if (!output) {
		return NULL;
	} else {
		output->exchange_type = 'o';
	}

        /* Sanity Check */
        if (length < 18) {
		DESTROY_DECODED_HASH(output, itr);
                return NULL;
        }

	/* Copy file name length. */
        bcopy(&buffer[16], &filename_length, sizeof(unsigned short));

#ifdef __BIG_ENDIAN__
	/* If we're on Big Endian, i.e. Sparc, convert to native endian. */
	filename_length = ((filename_length & 0xff) << 24) + ((filename_length & 0xff00) << 8) + ((filename_length & 0xff0000) >> 8) + ((filename_length >> 24) & 0xff);
#endif

	/* Sanity Check */
	if ((16 + filename_length) > length) {
		/* We may already have a hash, but really is it safe? */
		DESTROY_DECODED_HASH(output, itr);
		return NULL;
	}

	/* Allocate memory for filename. */
	filename = (char *) malloc (sizeof(char) * (filename_length + 1));
	bcopy(&buffer[18], filename, filename_length);
	filename[filename_length] = '\0';

	/* Clean it up to remove bad none printable characters. */
	sanitize_filename(filename, filename_length);

	/* Assign it. */
	output->filename = filename;

        /* Return hash. */
        return output;
}

