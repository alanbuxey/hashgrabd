#include <strings.h>

#include "capture.h"

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length) {
	unsigned char edonkey_id, edonkey_opcode;
	unsigned short ptr = 0;	
	unsigned int edonkey_length;
	struct decoded_hash *head = NULL, *tail = NULL;

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

		/* Is there enough room to read a packet length? */
		if (length < (ptr + sizeof(unsigned int))) {
			return head;
		}

		/* There is, copy it. NOTE: the length is already in little endian. */
		/* TODO - We must convert to host endian incase this runs on a Sparc or similar. */
		bcopy(&buffer[ptr], &edonkey_length, sizeof(unsigned int));
		ptr += sizeof(unsigned int);

		/* Is there enough data left in this packet to continue? If not we can't continue. */
		if (length < (ptr + edonkey_length)) {
			return head;
		}

		/* Grab the eDonkey opcode. */
		edonkey_opcode = buffer[ptr];
		ptr += sizeof(char);

		switch(edonkey_opcode) {
			case 0x19: /* Search Download Sources */
				printf("Find downloaded sources.\n");
				break;

			case 0x33: /* Return Search Results */
				printf("Return search resutls\n");
				break;
			case 0x42: /* Return download sources. */
				printf("Return download sources.\n");
				break;
			default:
				ptr += (edonkey_length - 1);
				break;
		}
	}

	return NULL;
} 
