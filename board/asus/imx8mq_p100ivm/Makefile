#
# Copyright 2016 Freescale Semiconductor
#
# SPDX-License-Identifier:      GPL-2.0+
#

obj-y += imx8mq_p100ivm.o ../common/mmc.o sku_id.o

ifdef CONFIG_SPL_BUILD
obj-y += spl.o sku_id.o
obj-$(CONFIG_IMX8M_LPDDR4) += lpddr4_timing.o lpddr4_timing_b0.o lpddr4_timing_micron_2gb.o lpddr4_timing_samsung_4gb.o
endif
