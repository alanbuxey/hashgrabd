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

#ifndef __EDONKEY_INTERNAL_H
#define __EDONKEY_INTERNAL_H 1

#include "edonkey.h"

struct eanimal {
	char *description;
	struct decoded_hash *(*pointer)(const u_char *, unsigned int, unsigned char, unsigned char, unsigned char *);
};

struct eanimal edonkey_tcp_table[] = {
	{ NULL, NULL }, /* 0x00 */
	{ "Login", NULL }, /* 0x01 */
	{ NULL, NULL }, /* 0x02 */
	{ NULL, NULL }, /* 0x03 */
	{ NULL, NULL }, /* 0x04 */
	{ "Message Rejected", NULL }, /* 0x05 */
	{ NULL, NULL }, /* 0x06 */
	{ NULL, NULL }, /* 0x07 */
	{ NULL, NULL }, /* 0x08 */
	{ NULL, NULL }, /* 0x09 */
	{ NULL, NULL }, /* 0x0a */
	{ NULL, NULL }, /* 0x0b */
	{ NULL, NULL }, /* 0x0c */
	{ NULL, NULL }, /* 0x0d */
	{ NULL, NULL }, /* 0x0e */
	{ NULL, NULL }, /* 0x0f */
	{ NULL, NULL }, /* 0x10 */
	{ NULL, NULL }, /* 0x11 */
	{ NULL, NULL }, /* 0x12 */
	{ NULL, NULL }, /* 0x13 */
	{ "Get List of Servers", NULL }, /* 0x14 */
	{ "Offer Files", NULL }, /* 0x15 */
	{ "Search Request/Result", NULL }, /* 0x16 */
	{ NULL, NULL }, /* 0x17 */
	{ NULL, NULL }, /* 0x18 */
	{ "Get Sources", NULL }, /* 0x19 */
	{ NULL, NULL }, /* 0x1a */
	{ NULL, NULL }, /* 0x1b */
	{ "Callback Request", NULL }, /* 0x1c */
	{ NULL, NULL }, /* 0x1d */
	{ NULL, NULL }, /* 0x1e */
	{ NULL, NULL }, /* 0x1f */
	{ NULL, NULL }, /* 0x20 */
	{ NULL, NULL }, /* 0x21 */
	{ NULL, NULL }, /* 0x22 */
	{ NULL, NULL }, /* 0x23 */
	{ NULL, NULL }, /* 0x24 */
	{ NULL, NULL }, /* 0x25 */
	{ NULL, NULL }, /* 0x26 */
	{ NULL, NULL }, /* 0x27 */
	{ NULL, NULL }, /* 0x28 */
	{ NULL, NULL }, /* 0x29 */
	{ NULL, NULL }, /* 0x2a */
	{ NULL, NULL }, /* 0x2b */
	{ NULL, NULL }, /* 0x2c */
	{ NULL, NULL }, /* 0x2d */
	{ NULL, NULL }, /* 0x2e */
	{ NULL, NULL }, /* 0x2f */
	{ NULL, NULL }, /* 0x30 */
	{ NULL, NULL }, /* 0x31 */
	{ "List of Servers", NULL }, /* 0x32 */
	{ NULL, NULL }, /* 0x33 */
	{ "Server Status", NULL }, /* 0x34 */
	{ "Callback Requested", NULL }, /* 0x35 */
	{ "Callback Failed", NULL }, /* 0x36 */
	{ NULL, NULL }, /* 0x37 */
	{ "Server Message", NULL }, /* 0x38 */
	{ NULL, NULL }, /* 0x39 */
	{ NULL, NULL }, /* 0x3a */
	{ NULL, NULL }, /* 0x3b */
	{ NULL, NULL }, /* 0x3c */
	{ NULL, NULL }, /* 0x3d */
	{ NULL, NULL }, /* 0x3e */
	{ NULL, NULL }, /* 0x3f */
	{ "ID Change", NULL }, /* 0x40 */
	{ "Server Identification", NULL }, /* 0x41 */
	{ "Found Sources", NULL }, /* 0x42 */
	{ NULL, NULL }, /* 0x43 */
	{ NULL, NULL }, /* 0x44 */
	{ NULL, NULL }, /* 0x45 */
	{ "Sending File Part", NULL }, /* 0x46 */
	{ "Request File Parts", &edonkey_tcp_0x58 }, /* 0x47 */
	{ "File Not Found", NULL }, /* 0x48 */
	{ "End of Download", NULL }, /* 0x49 */
	{ "View Shared Files", NULL }, /* 0x4a */
	{ "View Shared Files Answer", NULL }, /* 0x4b */
	{ "Hello Answer", NULL }, /* 0x4c */
	{ "Change Client ID", NULL }, /* 0x4d */
	{ "Chat Message / Requested File ID", NULL }, /* 0x4e */
	{ NULL, NULL }, /* 0x4f */
	{ "File Status", NULL }, /* 0x50 */
	{ "Part Hashset Request", NULL }, /* 0x51 */
	{ "Part Hashset Reply", NULL }, /* 0x52 */
	{ NULL, NULL }, /* 0x53 */
	{ "Start Upload Request", NULL }, /* 0x54 */
	{ "Accept Upload Request", NULL }, /* 0x55 */
	{ "Cancel Transfer", NULL }, /* 0x56 */
	{ "Out of Parts Request", NULL }, /* 0x57 */
	{ "File Request", &edonkey_tcp_0x58 }, /* 0x58 */
	{ "File Request Answer", &edonkey_tcp_0x59 }, /* 0x59 */
	{ NULL, NULL }, /* 0x5a */
	{ "Change Slot", NULL }, /* 0x5b */
	{ "Queue Rank", NULL }, /* 0x5c */
	{ "View Shared Folders", NULL }, /* 0x5d */
	{ "View Content of a Shared Folder", NULL }, /* 0x5e */
	{ "View Shared Folders Answer", NULL }, /* 0x5f */
	{ "View Shared Folder Content Answer", NULL }, /* 0x60 */
	{ "View Shared Folder or Content Denied", NULL }, /* 0x61 */
	{ NULL, NULL }, /* 0x62 */
	{ NULL, NULL }, /* 0x63 */
	{ NULL, NULL }, /* 0x64 */
	{ NULL, NULL }, /* 0x65 */
	{ NULL, NULL }, /* 0x66 */
	{ NULL, NULL }, /* 0x67 */
	{ NULL, NULL }, /* 0x68 */
	{ NULL, NULL }, /* 0x69 */
	{ NULL, NULL }, /* 0x6a */
	{ NULL, NULL }, /* 0x6b */
	{ NULL, NULL }, /* 0x6c */
	{ NULL, NULL }, /* 0x6d */
	{ NULL, NULL }, /* 0x6e */
	{ NULL, NULL }, /* 0x6f */
	{ NULL, NULL }, /* 0x70 */
	{ NULL, NULL }, /* 0x71 */
	{ NULL, NULL }, /* 0x72 */
	{ NULL, NULL }, /* 0x73 */
	{ NULL, NULL }, /* 0x74 */
	{ NULL, NULL }, /* 0x75 */
	{ NULL, NULL }, /* 0x76 */
	{ NULL, NULL }, /* 0x77 */
	{ NULL, NULL }, /* 0x78 */
	{ NULL, NULL }, /* 0x79 */
	{ NULL, NULL }, /* 0x7a */
	{ NULL, NULL }, /* 0x7b */
	{ NULL, NULL }, /* 0x7c */
	{ NULL, NULL }, /* 0x7d */
	{ NULL, NULL }, /* 0x7e */
	{ NULL, NULL }, /* 0x7f */
	{ NULL, NULL }, /* 0x80 */
	{ NULL, NULL }, /* 0x81 */
	{ NULL, NULL }, /* 0x82 */
	{ NULL, NULL }, /* 0x83 */
	{ NULL, NULL }, /* 0x84 */
	{ NULL, NULL }, /* 0x85 */
	{ NULL, NULL }, /* 0x86 */
	{ NULL, NULL }, /* 0x87 */
	{ NULL, NULL }, /* 0x88 */
	{ NULL, NULL }, /* 0x89 */
	{ NULL, NULL }, /* 0x8a */
	{ NULL, NULL }, /* 0x8b */
	{ NULL, NULL }, /* 0x8c */
	{ NULL, NULL }, /* 0x8d */
	{ NULL, NULL }, /* 0x8e */
	{ NULL, NULL }, /* 0x8f */
	{ NULL, NULL }, /* 0x90 */
	{ NULL, NULL }, /* 0x91 */
	{ NULL, NULL }, /* 0x92 */
	{ NULL, NULL }, /* 0x93 */
	{ NULL, NULL }, /* 0x94 */
	{ NULL, NULL }, /* 0x95 */
	{ NULL, NULL }, /* 0x96 */
	{ NULL, NULL }, /* 0x97 */
	{ NULL, NULL }, /* 0x98 */
	{ NULL, NULL }, /* 0x99 */
	{ NULL, NULL }, /* 0x9a */
	{ NULL, NULL }, /* 0x9b */
	{ NULL, NULL }, /* 0x9c */
	{ NULL, NULL }, /* 0x9d */
	{ NULL, NULL }, /* 0x9e */
	{ NULL, NULL }, /* 0x9f */
	{ NULL, NULL }, /* 0xa0 */
	{ NULL, NULL }, /* 0xa1 */
	{ NULL, NULL }, /* 0xa2 */
	{ NULL, NULL }, /* 0xa3 */
	{ NULL, NULL }, /* 0xa4 */
	{ NULL, NULL }, /* 0xa5 */
	{ NULL, NULL }, /* 0xa6 */
	{ NULL, NULL }, /* 0xa7 */
	{ NULL, NULL }, /* 0xa8 */
	{ NULL, NULL }, /* 0xa9 */
	{ NULL, NULL }, /* 0xaa */
	{ NULL, NULL }, /* 0xab */
	{ NULL, NULL }, /* 0xac */
	{ NULL, NULL }, /* 0xad */
	{ NULL, NULL }, /* 0xae */
	{ NULL, NULL }, /* 0xaf */
	{ NULL, NULL }, /* 0xb0 */
	{ NULL, NULL }, /* 0xb1 */
	{ NULL, NULL }, /* 0xb2 */
	{ NULL, NULL }, /* 0xb3 */
	{ NULL, NULL }, /* 0xb4 */
	{ NULL, NULL }, /* 0xb5 */
	{ NULL, NULL }, /* 0xb6 */
	{ NULL, NULL }, /* 0xb7 */
	{ NULL, NULL }, /* 0xb8 */
	{ NULL, NULL }, /* 0xb9 */
	{ NULL, NULL }, /* 0xba */
	{ NULL, NULL }, /* 0xbb */
	{ NULL, NULL }, /* 0xbc */
	{ NULL, NULL }, /* 0xbd */
	{ NULL, NULL }, /* 0xbe */
	{ NULL, NULL }, /* 0xbf */
	{ NULL, NULL }, /* 0xc0 */
	{ NULL, NULL }, /* 0xc1 */
	{ NULL, NULL }, /* 0xc2 */
	{ NULL, NULL }, /* 0xc3 */
	{ NULL, NULL }, /* 0xc4 */
	{ NULL, NULL }, /* 0xc5 */
	{ NULL, NULL }, /* 0xc6 */
	{ NULL, NULL }, /* 0xc7 */
	{ NULL, NULL }, /* 0xc8 */
	{ NULL, NULL }, /* 0xc9 */
	{ NULL, NULL }, /* 0xca */
	{ NULL, NULL }, /* 0xcb */
	{ NULL, NULL }, /* 0xcc */
	{ NULL, NULL }, /* 0xcd */
	{ NULL, NULL }, /* 0xce */
	{ NULL, NULL }, /* 0xcf */
	{ NULL, NULL }, /* 0xd0 */
	{ NULL, NULL }, /* 0xd1 */
	{ NULL, NULL }, /* 0xd2 */
	{ NULL, NULL }, /* 0xd3 */
	{ NULL, NULL }, /* 0xd4 */
	{ NULL, NULL }, /* 0xd5 */
	{ NULL, NULL }, /* 0xd6 */
	{ NULL, NULL }, /* 0xd7 */
	{ NULL, NULL }, /* 0xd8 */
	{ NULL, NULL }, /* 0xd9 */
	{ NULL, NULL }, /* 0xda */
	{ NULL, NULL }, /* 0xdb */
	{ NULL, NULL }, /* 0xdc */
	{ NULL, NULL }, /* 0xdd */
	{ NULL, NULL }, /* 0xde */
	{ NULL, NULL }, /* 0xdf */
	{ NULL, NULL }, /* 0xe0 */
	{ NULL, NULL }, /* 0xe1 */
	{ NULL, NULL }, /* 0xe2 */
	{ NULL, NULL }, /* 0xe3 */
	{ NULL, NULL }, /* 0xe4 */
	{ NULL, NULL }, /* 0xe5 */
	{ NULL, NULL }, /* 0xe6 */
	{ NULL, NULL }, /* 0xe7 */
	{ NULL, NULL }, /* 0xe8 */
	{ NULL, NULL }, /* 0xe9 */
	{ NULL, NULL }, /* 0xea */
	{ NULL, NULL }, /* 0xeb */
	{ NULL, NULL }, /* 0xec */
	{ NULL, NULL }, /* 0xed */
	{ NULL, NULL }, /* 0xee */
	{ NULL, NULL }, /* 0xef */
	{ NULL, NULL }, /* 0xf0 */
	{ NULL, NULL }, /* 0xf1 */
	{ NULL, NULL }, /* 0xf2 */
	{ NULL, NULL }, /* 0xf3 */
	{ NULL, NULL }, /* 0xf4 */
	{ NULL, NULL }, /* 0xf5 */
	{ NULL, NULL }, /* 0xf6 */
	{ NULL, NULL }, /* 0xf7 */
	{ NULL, NULL }, /* 0xf8 */
	{ NULL, NULL }, /* 0xf9 */
	{ NULL, NULL }, /* 0xfa */
	{ NULL, NULL }, /* 0xfb */
	{ NULL, NULL }, /* 0xfc */
	{ NULL, NULL }, /* 0xfd */
	{ NULL, NULL }, /* 0xfe */
	{ NULL, NULL }  /* 0xff */
};

struct eanimal edonkey_udp_table[] = {
	{ NULL, NULL }, /* 0x00 */
	{ NULL, NULL }, /* 0x01 */
	{ NULL, NULL }, /* 0x02 */
	{ NULL, NULL }, /* 0x03 */
	{ NULL, NULL }, /* 0x04 */
	{ NULL, NULL }, /* 0x05 */
	{ NULL, NULL }, /* 0x06 */
	{ NULL, NULL }, /* 0x07 */
	{ NULL, NULL }, /* 0x08 */
	{ NULL, NULL }, /* 0x09 */
	{ NULL, NULL }, /* 0x0a */
	{ NULL, NULL }, /* 0x0b */
	{ NULL, NULL }, /* 0x0c */
	{ NULL, NULL }, /* 0x0d */
	{ NULL, NULL }, /* 0x0e */
	{ NULL, NULL }, /* 0x0f */
	{ NULL, NULL }, /* 0x10 */
	{ NULL, NULL }, /* 0x11 */
	{ NULL, NULL }, /* 0x12 */
	{ NULL, NULL }, /* 0x13 */
	{ NULL, NULL }, /* 0x14 */
	{ NULL, NULL }, /* 0x15 */
	{ NULL, NULL }, /* 0x16 */
	{ NULL, NULL }, /* 0x17 */
	{ NULL, NULL }, /* 0x18 */
	{ NULL, NULL }, /* 0x19 */
	{ NULL, NULL }, /* 0x1a */
	{ NULL, NULL }, /* 0x1b */
	{ NULL, NULL }, /* 0x1c */
	{ NULL, NULL }, /* 0x1d */
	{ NULL, NULL }, /* 0x1e */
	{ NULL, NULL }, /* 0x1f */
	{ NULL, NULL }, /* 0x20 */
	{ NULL, NULL }, /* 0x21 */
	{ NULL, NULL }, /* 0x22 */
	{ NULL, NULL }, /* 0x23 */
	{ NULL, NULL }, /* 0x24 */
	{ NULL, NULL }, /* 0x25 */
	{ NULL, NULL }, /* 0x26 */
	{ NULL, NULL }, /* 0x27 */
	{ NULL, NULL }, /* 0x28 */
	{ NULL, NULL }, /* 0x29 */
	{ NULL, NULL }, /* 0x2a */
	{ NULL, NULL }, /* 0x2b */
	{ NULL, NULL }, /* 0x2c */
	{ NULL, NULL }, /* 0x2d */
	{ NULL, NULL }, /* 0x2e */
	{ NULL, NULL }, /* 0x2f */
	{ NULL, NULL }, /* 0x30 */
	{ NULL, NULL }, /* 0x31 */
	{ NULL, NULL }, /* 0x32 */
	{ NULL, NULL }, /* 0x33 */
	{ NULL, NULL }, /* 0x34 */
	{ NULL, NULL }, /* 0x35 */
	{ NULL, NULL }, /* 0x36 */
	{ NULL, NULL }, /* 0x37 */
	{ NULL, NULL }, /* 0x38 */
	{ NULL, NULL }, /* 0x39 */
	{ NULL, NULL }, /* 0x3a */
	{ NULL, NULL }, /* 0x3b */
	{ NULL, NULL }, /* 0x3c */
	{ NULL, NULL }, /* 0x3d */
	{ NULL, NULL }, /* 0x3e */
	{ NULL, NULL }, /* 0x3f */
	{ NULL, NULL }, /* 0x40 */
	{ NULL, NULL }, /* 0x41 */
	{ NULL, NULL }, /* 0x42 */
	{ NULL, NULL }, /* 0x43 */
	{ NULL, NULL }, /* 0x44 */
	{ NULL, NULL }, /* 0x45 */
	{ NULL, NULL }, /* 0x46 */
	{ NULL, NULL }, /* 0x47 */
	{ NULL, NULL }, /* 0x48 */
	{ NULL, NULL }, /* 0x49 */
	{ NULL, NULL }, /* 0x4a */
	{ NULL, NULL }, /* 0x4b */
	{ NULL, NULL }, /* 0x4c */
	{ NULL, NULL }, /* 0x4d */
	{ NULL, NULL }, /* 0x4e */
	{ NULL, NULL }, /* 0x4f */
	{ NULL, NULL }, /* 0x50 */
	{ NULL, NULL }, /* 0x51 */
	{ NULL, NULL }, /* 0x52 */
	{ NULL, NULL }, /* 0x53 */
	{ NULL, NULL }, /* 0x54 */
	{ NULL, NULL }, /* 0x55 */
	{ NULL, NULL }, /* 0x56 */
	{ NULL, NULL }, /* 0x57 */
	{ NULL, NULL }, /* 0x58 */
	{ NULL, NULL }, /* 0x59 */
	{ NULL, NULL }, /* 0x5a */
	{ NULL, NULL }, /* 0x5b */
	{ NULL, NULL }, /* 0x5c */
	{ NULL, NULL }, /* 0x5d */
	{ NULL, NULL }, /* 0x5e */
	{ NULL, NULL }, /* 0x5f */
	{ NULL, NULL }, /* 0x60 */
	{ NULL, NULL }, /* 0x61 */
	{ NULL, NULL }, /* 0x62 */
	{ NULL, NULL }, /* 0x63 */
	{ NULL, NULL }, /* 0x64 */
	{ NULL, NULL }, /* 0x65 */
	{ NULL, NULL }, /* 0x66 */
	{ NULL, NULL }, /* 0x67 */
	{ NULL, NULL }, /* 0x68 */
	{ NULL, NULL }, /* 0x69 */
	{ NULL, NULL }, /* 0x6a */
	{ NULL, NULL }, /* 0x6b */
	{ NULL, NULL }, /* 0x6c */
	{ NULL, NULL }, /* 0x6d */
	{ NULL, NULL }, /* 0x6e */
	{ NULL, NULL }, /* 0x6f */
	{ NULL, NULL }, /* 0x70 */
	{ NULL, NULL }, /* 0x71 */
	{ NULL, NULL }, /* 0x72 */
	{ NULL, NULL }, /* 0x73 */
	{ NULL, NULL }, /* 0x74 */
	{ NULL, NULL }, /* 0x75 */
	{ NULL, NULL }, /* 0x76 */
	{ NULL, NULL }, /* 0x77 */
	{ NULL, NULL }, /* 0x78 */
	{ NULL, NULL }, /* 0x79 */
	{ NULL, NULL }, /* 0x7a */
	{ NULL, NULL }, /* 0x7b */
	{ NULL, NULL }, /* 0x7c */
	{ NULL, NULL }, /* 0x7d */
	{ NULL, NULL }, /* 0x7e */
	{ NULL, NULL }, /* 0x7f */
	{ NULL, NULL }, /* 0x80 */
	{ NULL, NULL }, /* 0x81 */
	{ NULL, NULL }, /* 0x82 */
	{ NULL, NULL }, /* 0x83 */
	{ NULL, NULL }, /* 0x84 */
	{ NULL, NULL }, /* 0x85 */
	{ NULL, NULL }, /* 0x86 */
	{ NULL, NULL }, /* 0x87 */
	{ NULL, NULL }, /* 0x88 */
	{ NULL, NULL }, /* 0x89 */
	{ NULL, NULL }, /* 0x8a */
	{ NULL, NULL }, /* 0x8b */
	{ NULL, NULL }, /* 0x8c */
	{ NULL, NULL }, /* 0x8d */
	{ NULL, NULL }, /* 0x8e */
	{ NULL, NULL }, /* 0x8f */
	{ NULL, NULL }, /* 0x90 */
	{ NULL, NULL }, /* 0x91 */
	{ "Search Request", NULL }, /* 0x92 */
	{ NULL, NULL }, /* 0x93 */
	{ NULL, NULL }, /* 0x94 */
	{ NULL, NULL }, /* 0x95 */
	{ "Status Request", NULL }, /* 0x96 */
	{ "Status Response", NULL }, /* 0x97 */
	{ "Search Request", NULL }, /* 0x98 */
	{ "Search Response", NULL }, /* 0x99 */
	{ "Get Sources", NULL }, /* 0x9a */
	{ "Found Sources", NULL }, /* 0x9b */
	{ NULL, NULL }, /* 0x9c */
	{ NULL, NULL }, /* 0x9d */
	{ NULL, NULL }, /* 0x9e */
	{ NULL, NULL }, /* 0x9f */
	{ NULL, NULL }, /* 0xa0 */
	{ NULL, NULL }, /* 0xa1 */
	{ "Server Description Request", NULL }, /* 0xa2 */
	{ "Server Description Responce", NULL }, /* 0xa3 */
	{ NULL, NULL }, /* 0xa4 */
	{ NULL, NULL }, /* 0xa5 */
	{ NULL, NULL }, /* 0xa6 */
	{ NULL, NULL }, /* 0xa7 */
	{ NULL, NULL }, /* 0xa8 */
	{ NULL, NULL }, /* 0xa9 */
	{ NULL, NULL }, /* 0xaa */
	{ NULL, NULL }, /* 0xab */
	{ NULL, NULL }, /* 0xac */
	{ NULL, NULL }, /* 0xad */
	{ NULL, NULL }, /* 0xae */
	{ NULL, NULL }, /* 0xaf */
	{ NULL, NULL }, /* 0xb0 */
	{ NULL, NULL }, /* 0xb1 */
	{ NULL, NULL }, /* 0xb2 */
	{ NULL, NULL }, /* 0xb3 */
	{ NULL, NULL }, /* 0xb4 */
	{ NULL, NULL }, /* 0xb5 */
	{ NULL, NULL }, /* 0xb6 */
	{ NULL, NULL }, /* 0xb7 */
	{ NULL, NULL }, /* 0xb8 */
	{ NULL, NULL }, /* 0xb9 */
	{ NULL, NULL }, /* 0xba */
	{ NULL, NULL }, /* 0xbb */
	{ NULL, NULL }, /* 0xbc */
	{ NULL, NULL }, /* 0xbd */
	{ NULL, NULL }, /* 0xbe */
	{ NULL, NULL }, /* 0xbf */
	{ NULL, NULL }, /* 0xc0 */
	{ NULL, NULL }, /* 0xc1 */
	{ NULL, NULL }, /* 0xc2 */
	{ NULL, NULL }, /* 0xc3 */
	{ NULL, NULL }, /* 0xc4 */
	{ NULL, NULL }, /* 0xc5 */
	{ NULL, NULL }, /* 0xc6 */
	{ NULL, NULL }, /* 0xc7 */
	{ NULL, NULL }, /* 0xc8 */
	{ NULL, NULL }, /* 0xc9 */
	{ NULL, NULL }, /* 0xca */
	{ NULL, NULL }, /* 0xcb */
	{ NULL, NULL }, /* 0xcc */
	{ NULL, NULL }, /* 0xcd */
	{ NULL, NULL }, /* 0xce */
	{ NULL, NULL }, /* 0xcf */
	{ NULL, NULL }, /* 0xd0 */
	{ NULL, NULL }, /* 0xd1 */
	{ NULL, NULL }, /* 0xd2 */
	{ NULL, NULL }, /* 0xd3 */
	{ NULL, NULL }, /* 0xd4 */
	{ NULL, NULL }, /* 0xd5 */
	{ NULL, NULL }, /* 0xd6 */
	{ NULL, NULL }, /* 0xd7 */
	{ NULL, NULL }, /* 0xd8 */
	{ NULL, NULL }, /* 0xd9 */
	{ NULL, NULL }, /* 0xda */
	{ NULL, NULL }, /* 0xdb */
	{ NULL, NULL }, /* 0xdc */
	{ NULL, NULL }, /* 0xdd */
	{ NULL, NULL }, /* 0xde */
	{ NULL, NULL }, /* 0xdf */
	{ NULL, NULL }, /* 0xe0 */
	{ NULL, NULL }, /* 0xe1 */
	{ NULL, NULL }, /* 0xe2 */
	{ NULL, NULL }, /* 0xe3 */
	{ NULL, NULL }, /* 0xe4 */
	{ NULL, NULL }, /* 0xe5 */
	{ NULL, NULL }, /* 0xe6 */
	{ NULL, NULL }, /* 0xe7 */
	{ NULL, NULL }, /* 0xe8 */
	{ NULL, NULL }, /* 0xe9 */
	{ NULL, NULL }, /* 0xea */
	{ NULL, NULL }, /* 0xeb */
	{ NULL, NULL }, /* 0xec */
	{ NULL, NULL }, /* 0xed */
	{ NULL, NULL }, /* 0xee */
	{ NULL, NULL }, /* 0xef */
	{ NULL, NULL }, /* 0xf0 */
	{ NULL, NULL }, /* 0xf1 */
	{ NULL, NULL }, /* 0xf2 */
	{ NULL, NULL }, /* 0xf3 */
	{ NULL, NULL }, /* 0xf4 */
	{ NULL, NULL }, /* 0xf5 */
	{ NULL, NULL }, /* 0xf6 */
	{ NULL, NULL }, /* 0xf7 */
	{ NULL, NULL }, /* 0xf8 */
	{ NULL, NULL }, /* 0xf9 */
	{ NULL, NULL }, /* 0xfa */
	{ NULL, NULL }, /* 0xfb */
	{ NULL, NULL }, /* 0xfc */
	{ NULL, NULL }, /* 0xfd */
	{ NULL, NULL }, /* 0xfe */
	{ NULL, NULL }  /* 0xff */
};

struct eanimal emule_tcp_table[] = {
	{ NULL, NULL }, /* 0x00 */
	{ "eMule Info", NULL }, /* 0x01 */
	{ "eMule Info Answer", NULL }, /* 0x02 */
	{ NULL, NULL }, /* 0x03 */
	{ NULL, NULL }, /* 0x04 */
	{ NULL, NULL }, /* 0x05 */
	{ NULL, NULL }, /* 0x06 */
	{ NULL, NULL }, /* 0x07 */
	{ NULL, NULL }, /* 0x08 */
	{ NULL, NULL }, /* 0x09 */
	{ NULL, NULL }, /* 0x0a */
	{ NULL, NULL }, /* 0x0b */
	{ NULL, NULL }, /* 0x0c */
	{ NULL, NULL }, /* 0x0d */
	{ NULL, NULL }, /* 0x0e */
	{ NULL, NULL }, /* 0x0f */
	{ NULL, NULL }, /* 0x10 */
	{ NULL, NULL }, /* 0x11 */
	{ NULL, NULL }, /* 0x12 */
	{ NULL, NULL }, /* 0x13 */
	{ NULL, NULL }, /* 0x14 */
	{ NULL, NULL }, /* 0x15 */
	{ NULL, NULL }, /* 0x16 */
	{ NULL, NULL }, /* 0x17 */
	{ NULL, NULL }, /* 0x18 */
	{ NULL, NULL }, /* 0x19 */
	{ NULL, NULL }, /* 0x1a */
	{ NULL, NULL }, /* 0x1b */
	{ NULL, NULL }, /* 0x1c */
	{ NULL, NULL }, /* 0x1d */
	{ NULL, NULL }, /* 0x1e */
	{ NULL, NULL }, /* 0x1f */
	{ NULL, NULL }, /* 0x20 */
	{ NULL, NULL }, /* 0x21 */
	{ NULL, NULL }, /* 0x22 */
	{ NULL, NULL }, /* 0x23 */
	{ NULL, NULL }, /* 0x24 */
	{ NULL, NULL }, /* 0x25 */
	{ NULL, NULL }, /* 0x26 */
	{ NULL, NULL }, /* 0x27 */
	{ NULL, NULL }, /* 0x28 */
	{ NULL, NULL }, /* 0x29 */
	{ NULL, NULL }, /* 0x2a */
	{ NULL, NULL }, /* 0x2b */
	{ NULL, NULL }, /* 0x2c */
	{ NULL, NULL }, /* 0x2d */
	{ NULL, NULL }, /* 0x2e */
	{ NULL, NULL }, /* 0x2f */
	{ NULL, NULL }, /* 0x30 */
	{ NULL, NULL }, /* 0x31 */
	{ NULL, NULL }, /* 0x32 */
	{ NULL, NULL }, /* 0x33 */
	{ NULL, NULL }, /* 0x34 */
	{ NULL, NULL }, /* 0x35 */
	{ NULL, NULL }, /* 0x36 */
	{ NULL, NULL }, /* 0x37 */
	{ NULL, NULL }, /* 0x38 */
	{ NULL, NULL }, /* 0x39 */
	{ NULL, NULL }, /* 0x3a */
	{ NULL, NULL }, /* 0x3b */
	{ NULL, NULL }, /* 0x3c */
	{ NULL, NULL }, /* 0x3d */
	{ NULL, NULL }, /* 0x3e */
	{ NULL, NULL }, /* 0x3f */
	{ "Sending Compressed File Part", NULL }, /* 0x40 */
	{ NULL, NULL }, /* 0x41 */
	{ NULL, NULL }, /* 0x42 */
	{ NULL, NULL }, /* 0x43 */
	{ NULL, NULL }, /* 0x44 */
	{ NULL, NULL }, /* 0x45 */
	{ NULL, NULL }, /* 0x46 */
	{ NULL, NULL }, /* 0x47 */
	{ NULL, NULL }, /* 0x48 */
	{ NULL, NULL }, /* 0x49 */
	{ NULL, NULL }, /* 0x4a */
	{ NULL, NULL }, /* 0x4b */
	{ NULL, NULL }, /* 0x4c */
	{ NULL, NULL }, /* 0x4d */
	{ NULL, NULL }, /* 0x4e */
	{ NULL, NULL }, /* 0x4f */
	{ NULL, NULL }, /* 0x50 */
	{ NULL, NULL }, /* 0x51 */
	{ NULL, NULL }, /* 0x52 */
	{ NULL, NULL }, /* 0x53 */
	{ NULL, NULL }, /* 0x54 */
	{ NULL, NULL }, /* 0x55 */
	{ NULL, NULL }, /* 0x56 */
	{ NULL, NULL }, /* 0x57 */
	{ NULL, NULL }, /* 0x58 */
	{ NULL, NULL }, /* 0x59 */
	{ NULL, NULL }, /* 0x5a */
	{ NULL, NULL }, /* 0x5b */
	{ NULL, NULL }, /* 0x5c */
	{ NULL, NULL }, /* 0x5d */
	{ NULL, NULL }, /* 0x5e */
	{ NULL, NULL }, /* 0x5f */
	{ "Queue Ranking", NULL }, /* 0x60 */
	{ "File Info", NULL }, /* 0x61 */
	{ NULL, NULL }, /* 0x62 */
	{ NULL, NULL }, /* 0x63 */
	{ NULL, NULL }, /* 0x64 */
	{ NULL, NULL }, /* 0x65 */
	{ NULL, NULL }, /* 0x66 */
	{ NULL, NULL }, /* 0x67 */
	{ NULL, NULL }, /* 0x68 */
	{ NULL, NULL }, /* 0x69 */
	{ NULL, NULL }, /* 0x6a */
	{ NULL, NULL }, /* 0x6b */
	{ NULL, NULL }, /* 0x6c */
	{ NULL, NULL }, /* 0x6d */
	{ NULL, NULL }, /* 0x6e */
	{ NULL, NULL }, /* 0x6f */
	{ NULL, NULL }, /* 0x70 */
	{ NULL, NULL }, /* 0x71 */
	{ NULL, NULL }, /* 0x72 */
	{ NULL, NULL }, /* 0x73 */
	{ NULL, NULL }, /* 0x74 */
	{ NULL, NULL }, /* 0x75 */
	{ NULL, NULL }, /* 0x76 */
	{ NULL, NULL }, /* 0x77 */
	{ NULL, NULL }, /* 0x78 */
	{ NULL, NULL }, /* 0x79 */
	{ NULL, NULL }, /* 0x7a */
	{ NULL, NULL }, /* 0x7b */
	{ NULL, NULL }, /* 0x7c */
	{ NULL, NULL }, /* 0x7d */
	{ NULL, NULL }, /* 0x7e */
	{ NULL, NULL }, /* 0x7f */
	{ NULL, NULL }, /* 0x80 */
	{ "Sources Request", NULL }, /* 0x81 */
	{ "Sources Answer", NULL }, /* 0x82 */
	{ NULL, NULL }, /* 0x83 */
	{ NULL, NULL }, /* 0x84 */
	{ "Public Key", NULL }, /* 0x85 */
	{ "Signature", NULL }, /* 0x86 */
	{ "Secure Identification", NULL }, /* 0x87 */
	{ NULL, NULL }, /* 0x88 */
	{ NULL, NULL }, /* 0x89 */
	{ NULL, NULL }, /* 0x8a */
	{ NULL, NULL }, /* 0x8b */
	{ NULL, NULL }, /* 0x8c */
	{ NULL, NULL }, /* 0x8d */
	{ NULL, NULL }, /* 0x8e */
	{ NULL, NULL }, /* 0x8f */
	{ "Preview Request", NULL }, /* 0x90 */
	{ "Preview Answer", NULL }, /* 0x91 */
	{ NULL, NULL }, /* 0x92 */
	{ "Multipart", NULL }, /* 0x93 */
	{ "Multipart Extensions", NULL }, /* 0x94 */
	{ NULL, NULL }, /* 0x95 */
	{ NULL, NULL }, /* 0x96 */
	{ NULL, NULL }, /* 0x97 */
	{ NULL, NULL }, /* 0x98 */
	{ NULL, NULL }, /* 0x99 */
	{ NULL, NULL }, /* 0x9a */
	{ NULL, NULL }, /* 0x9b */
	{ NULL, NULL }, /* 0x9c */
	{ NULL, NULL }, /* 0x9d */
	{ NULL, NULL }, /* 0x9e */
	{ NULL, NULL }, /* 0x9f */
	{ NULL, NULL }, /* 0xa0 */
	{ NULL, NULL }, /* 0xa1 */
	{ NULL, NULL }, /* 0xa2 */
	{ NULL, NULL }, /* 0xa3 */
	{ NULL, NULL }, /* 0xa4 */
	{ NULL, NULL }, /* 0xa5 */
	{ NULL, NULL }, /* 0xa6 */
	{ NULL, NULL }, /* 0xa7 */
	{ NULL, NULL }, /* 0xa8 */
	{ NULL, NULL }, /* 0xa9 */
	{ NULL, NULL }, /* 0xaa */
	{ NULL, NULL }, /* 0xab */
	{ NULL, NULL }, /* 0xac */
	{ NULL, NULL }, /* 0xad */
	{ NULL, NULL }, /* 0xae */
	{ NULL, NULL }, /* 0xaf */
	{ NULL, NULL }, /* 0xb0 */
	{ NULL, NULL }, /* 0xb1 */
	{ NULL, NULL }, /* 0xb2 */
	{ NULL, NULL }, /* 0xb3 */
	{ NULL, NULL }, /* 0xb4 */
	{ NULL, NULL }, /* 0xb5 */
	{ NULL, NULL }, /* 0xb6 */
	{ NULL, NULL }, /* 0xb7 */
	{ NULL, NULL }, /* 0xb8 */
	{ NULL, NULL }, /* 0xb9 */
	{ NULL, NULL }, /* 0xba */
	{ NULL, NULL }, /* 0xbb */
	{ NULL, NULL }, /* 0xbc */
	{ NULL, NULL }, /* 0xbd */
	{ NULL, NULL }, /* 0xbe */
	{ NULL, NULL }, /* 0xbf */
	{ NULL, NULL }, /* 0xc0 */
	{ NULL, NULL }, /* 0xc1 */
	{ NULL, NULL }, /* 0xc2 */
	{ NULL, NULL }, /* 0xc3 */
	{ NULL, NULL }, /* 0xc4 */
	{ NULL, NULL }, /* 0xc5 */
	{ NULL, NULL }, /* 0xc6 */
	{ NULL, NULL }, /* 0xc7 */
	{ NULL, NULL }, /* 0xc8 */
	{ NULL, NULL }, /* 0xc9 */
	{ NULL, NULL }, /* 0xca */
	{ NULL, NULL }, /* 0xcb */
	{ NULL, NULL }, /* 0xcc */
	{ NULL, NULL }, /* 0xcd */
	{ NULL, NULL }, /* 0xce */
	{ NULL, NULL }, /* 0xcf */
	{ NULL, NULL }, /* 0xd0 */
	{ NULL, NULL }, /* 0xd1 */
	{ NULL, NULL }, /* 0xd2 */
	{ NULL, NULL }, /* 0xd3 */
	{ NULL, NULL }, /* 0xd4 */
	{ NULL, NULL }, /* 0xd5 */
	{ NULL, NULL }, /* 0xd6 */
	{ NULL, NULL }, /* 0xd7 */
	{ NULL, NULL }, /* 0xd8 */
	{ NULL, NULL }, /* 0xd9 */
	{ NULL, NULL }, /* 0xda */
	{ NULL, NULL }, /* 0xdb */
	{ NULL, NULL }, /* 0xdc */
	{ NULL, NULL }, /* 0xdd */
	{ NULL, NULL }, /* 0xde */
	{ NULL, NULL }, /* 0xdf */
	{ NULL, NULL }, /* 0xe0 */
	{ NULL, NULL }, /* 0xe1 */
	{ NULL, NULL }, /* 0xe2 */
	{ NULL, NULL }, /* 0xe3 */
	{ NULL, NULL }, /* 0xe4 */
	{ NULL, NULL }, /* 0xe5 */
	{ NULL, NULL }, /* 0xe6 */
	{ NULL, NULL }, /* 0xe7 */
	{ NULL, NULL }, /* 0xe8 */
	{ NULL, NULL }, /* 0xe9 */
	{ NULL, NULL }, /* 0xea */
	{ NULL, NULL }, /* 0xeb */
	{ NULL, NULL }, /* 0xec */
	{ NULL, NULL }, /* 0xed */
	{ NULL, NULL }, /* 0xee */
	{ NULL, NULL }, /* 0xef */
	{ NULL, NULL }, /* 0xf0 */
	{ NULL, NULL }, /* 0xf1 */
	{ NULL, NULL }, /* 0xf2 */
	{ NULL, NULL }, /* 0xf3 */
	{ NULL, NULL }, /* 0xf4 */
	{ NULL, NULL }, /* 0xf5 */
	{ NULL, NULL }, /* 0xf6 */
	{ NULL, NULL }, /* 0xf7 */
	{ NULL, NULL }, /* 0xf8 */
	{ NULL, NULL }, /* 0xf9 */
	{ NULL, NULL }, /* 0xfa */
	{ NULL, NULL }, /* 0xfb */
	{ NULL, NULL }, /* 0xfc */
	{ NULL, NULL }, /* 0xfd */
	{ NULL, NULL }, /* 0xfe */
	{ NULL, NULL }  /* 0xff */
};

struct eanimal emule_udp_table[] = {
	{ NULL, NULL }, /* 0x00 */
	{ NULL, NULL }, /* 0x01 */
	{ NULL, NULL }, /* 0x02 */
	{ NULL, NULL }, /* 0x03 */
	{ NULL, NULL }, /* 0x04 */
	{ NULL, NULL }, /* 0x05 */
	{ NULL, NULL }, /* 0x06 */
	{ NULL, NULL }, /* 0x07 */
	{ NULL, NULL }, /* 0x08 */
	{ NULL, NULL }, /* 0x09 */
	{ NULL, NULL }, /* 0x0a */
	{ NULL, NULL }, /* 0x0b */
	{ NULL, NULL }, /* 0x0c */
	{ NULL, NULL }, /* 0x0d */
	{ NULL, NULL }, /* 0x0e */
	{ NULL, NULL }, /* 0x0f */
	{ NULL, NULL }, /* 0x10 */
	{ NULL, NULL }, /* 0x11 */
	{ NULL, NULL }, /* 0x12 */
	{ NULL, NULL }, /* 0x13 */
	{ NULL, NULL }, /* 0x14 */
	{ NULL, NULL }, /* 0x15 */
	{ NULL, NULL }, /* 0x16 */
	{ NULL, NULL }, /* 0x17 */
	{ NULL, NULL }, /* 0x18 */
	{ NULL, NULL }, /* 0x19 */
	{ NULL, NULL }, /* 0x1a */
	{ NULL, NULL }, /* 0x1b */
	{ NULL, NULL }, /* 0x1c */
	{ NULL, NULL }, /* 0x1d */
	{ NULL, NULL }, /* 0x1e */
	{ NULL, NULL }, /* 0x1f */
	{ NULL, NULL }, /* 0x20 */
	{ NULL, NULL }, /* 0x21 */
	{ NULL, NULL }, /* 0x22 */
	{ NULL, NULL }, /* 0x23 */
	{ NULL, NULL }, /* 0x24 */
	{ NULL, NULL }, /* 0x25 */
	{ NULL, NULL }, /* 0x26 */
	{ NULL, NULL }, /* 0x27 */
	{ NULL, NULL }, /* 0x28 */
	{ NULL, NULL }, /* 0x29 */
	{ NULL, NULL }, /* 0x2a */
	{ NULL, NULL }, /* 0x2b */
	{ NULL, NULL }, /* 0x2c */
	{ NULL, NULL }, /* 0x2d */
	{ NULL, NULL }, /* 0x2e */
	{ NULL, NULL }, /* 0x2f */
	{ NULL, NULL }, /* 0x30 */
	{ NULL, NULL }, /* 0x31 */
	{ NULL, NULL }, /* 0x32 */
	{ NULL, NULL }, /* 0x33 */
	{ NULL, NULL }, /* 0x34 */
	{ NULL, NULL }, /* 0x35 */
	{ NULL, NULL }, /* 0x36 */
	{ NULL, NULL }, /* 0x37 */
	{ NULL, NULL }, /* 0x38 */
	{ NULL, NULL }, /* 0x39 */
	{ NULL, NULL }, /* 0x3a */
	{ NULL, NULL }, /* 0x3b */
	{ NULL, NULL }, /* 0x3c */
	{ NULL, NULL }, /* 0x3d */
	{ NULL, NULL }, /* 0x3e */
	{ NULL, NULL }, /* 0x3f */
	{ NULL, NULL }, /* 0x40 */
	{ NULL, NULL }, /* 0x41 */
	{ NULL, NULL }, /* 0x42 */
	{ NULL, NULL }, /* 0x43 */
	{ NULL, NULL }, /* 0x44 */
	{ NULL, NULL }, /* 0x45 */
	{ NULL, NULL }, /* 0x46 */
	{ NULL, NULL }, /* 0x47 */
	{ NULL, NULL }, /* 0x48 */
	{ NULL, NULL }, /* 0x49 */
	{ NULL, NULL }, /* 0x4a */
	{ NULL, NULL }, /* 0x4b */
	{ NULL, NULL }, /* 0x4c */
	{ NULL, NULL }, /* 0x4d */
	{ NULL, NULL }, /* 0x4e */
	{ NULL, NULL }, /* 0x4f */
	{ NULL, NULL }, /* 0x50 */
	{ NULL, NULL }, /* 0x51 */
	{ NULL, NULL }, /* 0x52 */
	{ NULL, NULL }, /* 0x53 */
	{ NULL, NULL }, /* 0x54 */
	{ NULL, NULL }, /* 0x55 */
	{ NULL, NULL }, /* 0x56 */
	{ NULL, NULL }, /* 0x57 */
	{ NULL, NULL }, /* 0x58 */
	{ NULL, NULL }, /* 0x59 */
	{ NULL, NULL }, /* 0x5a */
	{ NULL, NULL }, /* 0x5b */
	{ NULL, NULL }, /* 0x5c */
	{ NULL, NULL }, /* 0x5d */
	{ NULL, NULL }, /* 0x5e */
	{ NULL, NULL }, /* 0x5f */
	{ NULL, NULL }, /* 0x60 */
	{ NULL, NULL }, /* 0x61 */
	{ NULL, NULL }, /* 0x62 */
	{ NULL, NULL }, /* 0x63 */
	{ NULL, NULL }, /* 0x64 */
	{ NULL, NULL }, /* 0x65 */
	{ NULL, NULL }, /* 0x66 */
	{ NULL, NULL }, /* 0x67 */
	{ NULL, NULL }, /* 0x68 */
	{ NULL, NULL }, /* 0x69 */
	{ NULL, NULL }, /* 0x6a */
	{ NULL, NULL }, /* 0x6b */
	{ NULL, NULL }, /* 0x6c */
	{ NULL, NULL }, /* 0x6d */
	{ NULL, NULL }, /* 0x6e */
	{ NULL, NULL }, /* 0x6f */
	{ NULL, NULL }, /* 0x70 */
	{ NULL, NULL }, /* 0x71 */
	{ NULL, NULL }, /* 0x72 */
	{ NULL, NULL }, /* 0x73 */
	{ NULL, NULL }, /* 0x74 */
	{ NULL, NULL }, /* 0x75 */
	{ NULL, NULL }, /* 0x76 */
	{ NULL, NULL }, /* 0x77 */
	{ NULL, NULL }, /* 0x78 */
	{ NULL, NULL }, /* 0x79 */
	{ NULL, NULL }, /* 0x7a */
	{ NULL, NULL }, /* 0x7b */
	{ NULL, NULL }, /* 0x7c */
	{ NULL, NULL }, /* 0x7d */
	{ NULL, NULL }, /* 0x7e */
	{ NULL, NULL }, /* 0x7f */
	{ NULL, NULL }, /* 0x80 */
	{ NULL, NULL }, /* 0x81 */
	{ NULL, NULL }, /* 0x82 */
	{ NULL, NULL }, /* 0x83 */
	{ NULL, NULL }, /* 0x84 */
	{ NULL, NULL }, /* 0x85 */
	{ NULL, NULL }, /* 0x86 */
	{ NULL, NULL }, /* 0x87 */
	{ NULL, NULL }, /* 0x88 */
	{ NULL, NULL }, /* 0x89 */
	{ NULL, NULL }, /* 0x8a */
	{ NULL, NULL }, /* 0x8b */
	{ NULL, NULL }, /* 0x8c */
	{ NULL, NULL }, /* 0x8d */
	{ NULL, NULL }, /* 0x8e */
	{ NULL, NULL }, /* 0x8f */
	{ "Re-ask File", NULL }, /* 0x90 */
	{ "Re-ask File Ack", NULL }, /* 0x91 */
	{ "Re-ask File Ack - Not Found", NULL }, /* 0x92 */
	{ "Queue Full", NULL }, /* 0x93 */
	{ NULL, NULL }, /* 0x94 */
	{ NULL, NULL }, /* 0x95 */
	{ NULL, NULL }, /* 0x96 */
	{ NULL, NULL }, /* 0x97 */
	{ NULL, NULL }, /* 0x98 */
	{ NULL, NULL }, /* 0x99 */
	{ NULL, NULL }, /* 0x9a */
	{ NULL, NULL }, /* 0x9b */
	{ NULL, NULL }, /* 0x9c */
	{ NULL, NULL }, /* 0x9d */
	{ NULL, NULL }, /* 0x9e */
	{ NULL, NULL }, /* 0x9f */
	{ NULL, NULL }, /* 0xa0 */
	{ NULL, NULL }, /* 0xa1 */
	{ NULL, NULL }, /* 0xa2 */
	{ NULL, NULL }, /* 0xa3 */
	{ NULL, NULL }, /* 0xa4 */
	{ NULL, NULL }, /* 0xa5 */
	{ NULL, NULL }, /* 0xa6 */
	{ NULL, NULL }, /* 0xa7 */
	{ NULL, NULL }, /* 0xa8 */
	{ NULL, NULL }, /* 0xa9 */
	{ NULL, NULL }, /* 0xaa */
	{ NULL, NULL }, /* 0xab */
	{ NULL, NULL }, /* 0xac */
	{ NULL, NULL }, /* 0xad */
	{ NULL, NULL }, /* 0xae */
	{ NULL, NULL }, /* 0xaf */
	{ NULL, NULL }, /* 0xb0 */
	{ NULL, NULL }, /* 0xb1 */
	{ NULL, NULL }, /* 0xb2 */
	{ NULL, NULL }, /* 0xb3 */
	{ NULL, NULL }, /* 0xb4 */
	{ NULL, NULL }, /* 0xb5 */
	{ NULL, NULL }, /* 0xb6 */
	{ NULL, NULL }, /* 0xb7 */
	{ NULL, NULL }, /* 0xb8 */
	{ NULL, NULL }, /* 0xb9 */
	{ NULL, NULL }, /* 0xba */
	{ NULL, NULL }, /* 0xbb */
	{ NULL, NULL }, /* 0xbc */
	{ NULL, NULL }, /* 0xbd */
	{ NULL, NULL }, /* 0xbe */
	{ NULL, NULL }, /* 0xbf */
	{ NULL, NULL }, /* 0xc0 */
	{ NULL, NULL }, /* 0xc1 */
	{ NULL, NULL }, /* 0xc2 */
	{ NULL, NULL }, /* 0xc3 */
	{ NULL, NULL }, /* 0xc4 */
	{ NULL, NULL }, /* 0xc5 */
	{ NULL, NULL }, /* 0xc6 */
	{ NULL, NULL }, /* 0xc7 */
	{ NULL, NULL }, /* 0xc8 */
	{ NULL, NULL }, /* 0xc9 */
	{ NULL, NULL }, /* 0xca */
	{ NULL, NULL }, /* 0xcb */
	{ NULL, NULL }, /* 0xcc */
	{ NULL, NULL }, /* 0xcd */
	{ NULL, NULL }, /* 0xce */
	{ NULL, NULL }, /* 0xcf */
	{ NULL, NULL }, /* 0xd0 */
	{ NULL, NULL }, /* 0xd1 */
	{ NULL, NULL }, /* 0xd2 */
	{ NULL, NULL }, /* 0xd3 */
	{ NULL, NULL }, /* 0xd4 */
	{ NULL, NULL }, /* 0xd5 */
	{ NULL, NULL }, /* 0xd6 */
	{ NULL, NULL }, /* 0xd7 */
	{ NULL, NULL }, /* 0xd8 */
	{ NULL, NULL }, /* 0xd9 */
	{ NULL, NULL }, /* 0xda */
	{ NULL, NULL }, /* 0xdb */
	{ NULL, NULL }, /* 0xdc */
	{ NULL, NULL }, /* 0xdd */
	{ NULL, NULL }, /* 0xde */
	{ NULL, NULL }, /* 0xdf */
	{ NULL, NULL }, /* 0xe0 */
	{ NULL, NULL }, /* 0xe1 */
	{ NULL, NULL }, /* 0xe2 */
	{ NULL, NULL }, /* 0xe3 */
	{ NULL, NULL }, /* 0xe4 */
	{ NULL, NULL }, /* 0xe5 */
	{ NULL, NULL }, /* 0xe6 */
	{ NULL, NULL }, /* 0xe7 */
	{ NULL, NULL }, /* 0xe8 */
	{ NULL, NULL }, /* 0xe9 */
	{ NULL, NULL }, /* 0xea */
	{ NULL, NULL }, /* 0xeb */
	{ NULL, NULL }, /* 0xec */
	{ NULL, NULL }, /* 0xed */
	{ NULL, NULL }, /* 0xee */
	{ NULL, NULL }, /* 0xef */
	{ NULL, NULL }, /* 0xf0 */
	{ NULL, NULL }, /* 0xf1 */
	{ NULL, NULL }, /* 0xf2 */
	{ NULL, NULL }, /* 0xf3 */
	{ NULL, NULL }, /* 0xf4 */
	{ NULL, NULL }, /* 0xf5 */
	{ NULL, NULL }, /* 0xf6 */
	{ NULL, NULL }, /* 0xf7 */
	{ NULL, NULL }, /* 0xf8 */
	{ NULL, NULL }, /* 0xf9 */
	{ NULL, NULL }, /* 0xfa */
	{ NULL, NULL }, /* 0xfb */
	{ NULL, NULL }, /* 0xfc */
	{ NULL, NULL }, /* 0xfd */
	{ NULL, NULL }, /* 0xfe */
	{ NULL, NULL }  /* 0xff */
};

#endif
