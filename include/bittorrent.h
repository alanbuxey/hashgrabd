#ifndef __BITTORRENT_H
#define __BITTORRENT_H 1

struct decoded_hash *bittorrent_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump);

#endif
