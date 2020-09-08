#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <ctype.h>
#include "uint256.h"

int uint256_set_hex(uint256_t *t, char *psz)
{
    uint256_t data;
    int i;
    for (i = 0; i < 8; i++) {
        data.pn[i] = 0;
    }

    // skip leading spaces
    while (isspace(*psz)) {
        psz++;
    }

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x') {
        psz += 2;
    }

    // hex string to uint
    static unsigned char phexdigit[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 0, 0, 0, 0, 0, 0, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    const char *pbegin = psz;
    while (phexdigit[(unsigned char)*psz] || *psz == '0') {
        psz++;
    }

    psz--;

    unsigned char *p1 = (unsigned char *)data.pn;
    unsigned char *pend = p1 + 8 * 4;

    while (psz >= pbegin && p1 < pend) {
        *p1 = phexdigit[(unsigned char)*psz--];

        if (psz >= pbegin) {
            *p1 |= (phexdigit[(unsigned char)*psz--] << 4);
            p1++;
        }
    }

    memmove(t, &data, sizeof(data));

    return 0;
}

void uint256_get_hex(struct uint256_t *data, char *psz)
{
    unsigned int i;
    for (i = 0; i < sizeof(data->pn); i++) {
        sprintf(psz + i * 2, "%02x", ((unsigned char *)data->pn)[sizeof(data->pn) - i - 1]);
    }
}

int uint256_compare(uint256_t *data1, uint256_t *data2)
{
    int i;
    for (i = 7; i >= 0; i--) {
        // printf("%d, data1:%u, data2:%u\n", i, data1->pn[i], data2->pn[i]);
        if (data1->pn[i] > data2->pn[i]) {
            return 1;
        }

        if (data1->pn[i] == data2->pn[i]) {
            continue;
        }

        if (data1->pn[i] < data2->pn[i]) {
            return -1;
        }
    }

    return 0;
}