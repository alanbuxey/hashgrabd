#include <strings.h>
#include <stdlib.h>

#include "capture.h"

struct decoded_hash *bittorrent_decode(const u_char *buffer, unsigned short length) {
	char protocol_length, protocol_ident[20], *hash;
	unsigned short ptr = 0;
	struct decoded_hash *output;

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
