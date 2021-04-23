
obj-$(CONFIG_POWER_PFUZE100)    += pfuze.o
obj-$(CONFIG_DM_PMIC_PFUZE100)  += pfuze.o

obj-y += mmc.o

ifndef CONFIG_SPL_BUILD
obj-$(CONFIG_USB_TCPC) += tcpc.o
endif
