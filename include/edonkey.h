/*
 * Hashgrab - Utility to capture eDonkey and BitTorrent crytographic hashes from BPF.
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

#ifndef __EDONKEY_H
#define __EDONKEY_H 1

struct decoded_hash *edonkey_decode(const u_char *buffer, unsigned short length, unsigned char protocol, unsigned char *dump);
struct decoded_hash *edonkey_tcp_0x58(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump);
struct decoded_hash *edonkey_tcp_0x59(const u_char *buffer, unsigned int length, unsigned char opcode, unsigned char protocol, unsigned char *dump);

#endif
