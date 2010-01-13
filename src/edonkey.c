#include <strings.h>
#include <stdlib.h>

#include "capture.h"
#include "edonkey.h"

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump) {
	unsigned char edonkey_id, edonkey_opcode;
	unsigned short ptr = 0;	
	unsigned int edonkey_length;
	struct decoded_hash *head = NULL, *tail = NULL, *tmp = NULL;

	/* Can we read the first byte which should be e3 for eDonkey, do this outside of the loop first. */
	if (length < 1) {
		return NULL;
	}

	/* An eDonkey packet can contain many messages. We need to iterate throguh the entire packet to find them. */
	while (ptr < length) {
		/* Check the start of this subsection is eDonkey. */
		edonkey_id = buffer[ptr];
		ptr += sizeof(char);
		
		/* Return the head of the LL if the packet does not begin with e3. */
		if (edonkey_id != 0xe3) {
			return head;
		}

		/* If we're TCP then we have an appropriate size, if not UDP doesn't have this value. */
		if (protocol == 0x6) {
			/* Is there enough room to read a packet length? */
			if (length < (ptr + sizeof(unsigned int))) {
				return head;
			}

			/* There is, copy it. NOTE: the length is already in little endian. */
			/* TODO - We must convert to host endian incase this runs on a Sparc or similar. */
			bcopy(&buffer[ptr], &edonkey_length, sizeof(unsigned int));
			ptr += sizeof(unsigned int);
		} else {
			/* Assuming UDP packets, we don't get the edonkey length from the packet, so we must assume from the udp payload length. */
			edonkey_length = length - 1;
		}

                /* Is there enough data left in this packet to continue? If not we can't continue. */
                if (length < (ptr + edonkey_length)) {
                        return head;
                }

		/* Dump here we have an eDonkey packet. */

		/* Grab the eDonkey opcode. */
		edonkey_opcode = buffer[ptr];
		ptr += sizeof(char);

		switch(edonkey_opcode) {
			case 0x99:
		*dump = 1;

				tmp = edonkey_decode_search(buffer, length, edonkey_length, protocol, &ptr);
				break;

			default:
				ptr += (edonkey_length - 1);
				break;
		}
	}

	return NULL;
} 

struct decoded_hash *edonkey_decode_search(const u_char *buffer, unsigned short length, unsigned int edonkey_length, unsigned char protocol, unsigned short *ptr) {
	unsigned int number_results = 1;
	unsigned short base = *ptr;
	struct decoded_hash *head = NULL, *tail = NULL;
	unsigned char address[4];
	char *hash;

	/* If this is UDP then we do not have a result count, if it's TCP we do. */
	if (protocol == 0x6) {
		/* Do we have enough room to check for length. */
		if (length < (*ptr + sizeof(unsigned int))) {
			return NULL;
		}

		/* Copy number of results. */
		bcopy(&buffer[*ptr], &number_results, sizeof(unsigned int));
		*ptr += sizeof(unsigned int);
	}
	
	/* Cycle through results, making sure ptr less then the start of this sub packet and the sub packet length. */
	while (*ptr < (base + edonkey_length)) {
		/* Do we have enough data for the next 26 bytes of data? */
		if (length < (*ptr + 26)) {
			return head;
		}

		/* Allocate memory for hash and extract. */
		hash = (char *) malloc(sizeof(char) * 33);
		snprintf(hash, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", buffer[*ptr], buffer[*ptr+1], buffer[*ptr+2], buffer[*ptr+3], buffer[*ptr+4], buffer[*ptr+5], buffer[*ptr+6], buffer[*ptr+7], buffer[*ptr+8], buffer[*ptr+9], buffer[*ptr+10], buffer[*ptr+11], buffer[*ptr+12], buffer[*ptr+13], buffer[*ptr+14], buffer[*ptr+15]);
		*ptr += 16;
		
		/* Copy IP address. */
		bcopy(&buffer[*ptr], &address, sizeof(char) * 4);
		*ptr += 4;

printf("%s - %i.%i.%i.%i\n", hash, address[0], address[1], address[2], address[3]);

return NULL;

	}	

	return NULL;
}
