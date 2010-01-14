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
			/* TODO - We must convert to host endian incase this runs on a Sparc or similar. */
			bcopy(&buffer[ptr], &edonkey_length, sizeof(unsigned int));
			ptr += sizeof(unsigned int);

			/* Seem to need to remove a one. */
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
			tmp = lookup->pointer(&buffer[ptr], edonkey_length, edonkey_opcode, protocol, dump);
		}

		/* More the ptr along. */
		ptr += edonkey_length;

		/* Increase debug packet counter. */
		packets++;
	}

	return NULL;
} 

struct decoded_hash *edonkey_tcp_0x58(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump) {
	return NULL;
}

