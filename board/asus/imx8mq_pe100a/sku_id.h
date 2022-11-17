#ifndef __SKU_ID_H__
#define __SKU_ID_H__

#include <common.h>

#define SKU_MB_MICRON_4G	0
#define SKU_SYS_MICRON_4G	1
#define SKU_SAMSUNG_4G		3
#define SKU_MICRON_2G		5

int get_sku_id(void);

#endif

