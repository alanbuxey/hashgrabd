#ifndef __EDONKEY_H
#define __EDONKEY_H 1

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump);
struct decoded_hash *edonkey_decode_search(const u_char *buffer, unsigned short length, unsigned int edonkey_length, unsigned char protocol, unsigned short *ptr);

#endif
