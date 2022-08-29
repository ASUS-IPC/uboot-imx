#ifndef __SKU_ID_H__
#define __SKU_ID_H__

#include <common.h>

#define SKU_MICRON_4G	0
#define SKU_SAMSUNG_4G	1
#define SKU_MICRON_2G	2
#define SKU_SAMSUNG_2G	3

int get_sku_id(void);
int get_dram_bank(void);
phys_size_t get_ddr_size(void);

#endif

