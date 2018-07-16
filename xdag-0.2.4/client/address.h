/* addresses, T13.692-T13.692 $DVS:time$ */

#ifndef XDAG_ADDRESS_H
#define XDAG_ADDRESS_H

#include "hash.h"

/* intializes the addresses module */
/* 初始化地址模块 */
extern int xdag_address_init(void);

/* converts address to hash */
/* 地址转哈希 */
extern int xdag_address2hash(const char *address, xdag_hash_t hash);

/* converts hash to address */
/* 哈希转地址 */
extern void xdag_hash2address(const xdag_hash_t hash, char *address);

#endif
