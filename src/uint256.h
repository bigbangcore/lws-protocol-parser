#ifndef LWS_IOT_UINT256_H
#define LWS_IOT_UINT256_H

#include <stdint.h>

typedef struct uint256_t {
    uint32_t pn[8];
} uint256_t;

int uint256_set_hex(uint256_t *uint, char *psz);
void uint256_get_hex(uint256_t *data, char *psz);
int uint256_compare(uint256_t *data1, uint256_t *data2);

#endif