#ifndef __EDONKEY_H
#define __EDONKEY_H 1

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump);
struct decoded_hash *edonkey_tcp_0x58(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump);
struct decoded_hash *edonkey_tcp_0x59(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump);

#endif
