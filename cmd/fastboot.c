/*
 * Copyright 2008 - 2009 Windriver, <www.windriver.com>
 * Author: Tom Rix <Tom.Rix@windriver.com>
 *
 * (C) Copyright 2014 Linaro, Ltd.
 * Rob Herring <robh@kernel.org>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include <common.h>
#include <command.h>
#include <console.h>
#include <g_dnl.h>
#include <usb.h>
#include <asm/gpio.h>

#define GPIO1_IO13 13

static int do_fastboot(cmd_tbl_t *cmdtp, int flag, int argc, char *const argv[])
{
	int controller_index;
	char *usb_controller;
	int ret;

	if (argc < 2)
		return CMD_RET_USAGE;

	usb_controller = argv[1];
	controller_index = simple_strtoul(usb_controller, NULL, 0);
#ifdef CONFIG_FASTBOOT_USB_DEV
	controller_index = CONFIG_FASTBOOT_USB_DEV;
#endif

	ret = board_usb_init(controller_index, USB_INIT_DEVICE);
	if (ret) {
		pr_err("USB init failed: %d", ret);
		return CMD_RET_FAILURE;
	}

	g_dnl_clear_detach();
	ret = g_dnl_register("usb_dnl_fastboot");
	if (ret)
		return ret;

	if (!g_dnl_board_usb_cable_connected()) {
		puts("\rUSB cable not detected.\n" \
		     "Command exit.\n");
		ret = CMD_RET_FAILURE;
		goto exit;
	}

	gpio_request(GPIO1_IO13, "SOC_READY");
	gpio_direction_output(GPIO1_IO13, 0);

	while (1) {
		if (g_dnl_detach())
			break;
		if (ctrlc())
			break;
		usb_gadget_handle_interrupts(controller_index);
	}

	ret = CMD_RET_SUCCESS;

exit:
	g_dnl_unregister();
	g_dnl_clear_detach();
	board_usb_cleanup(controller_index, USB_INIT_DEVICE);

	return ret;
}

U_BOOT_CMD(
	fastboot, 2, 1, do_fastboot,
	"use USB Fastboot protocol",
	"<USB_controller>\n"
	"    - run as a fastboot usb device"
);
