/*
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <autoboot.h>
#include <bootretry.h>
#include <cli.h>
#include <console.h>
#include <fdtdec.h>
#include <menu.h>
#include <post.h>
#include <u-boot/sha256.h>
#include <asm/gpio.h>

#ifdef is_boot_from_usb
#include <environment.h>
#endif

DECLARE_GLOBAL_DATA_PTR;

#define MAX_DELAY_STOP_STR 32

#ifndef DEBUG_BOOTKEYS
#define DEBUG_BOOTKEYS 0
#endif
#define debug_bootkeys(fmt, args...)		\
	debug_cond(DEBUG_BOOTKEYS, fmt, ##args)

#define GPIO5_IO04 132

static char bootargs[1024] = {0};

static unsigned long hw_skip_comment(char *text)
{
	int i = 0;
	if(*text == '#') {
		while(*(text + i) != 0x00)
		{
			if(*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

static unsigned long hw_skip_line(char *text)
{
	if(*text == 0x0a)
		return 1;
	else
		return 0;
}

static unsigned long get_append(char *text)
{
	int i = 0;
	int append_len = 0;
	char append[1024] = {0};

	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x0a) {
			append_len = i;
			append[i] = 0x00;
			i++;
			break;
		} else {
			append[i] = *(text + i);
			i++;
		}
	}

	if (append_len)
		strcat(bootargs, append);

	env_set("bootargs", bootargs);

	return i;
}

static void set_bootargs(void)
{
	char *jh_clk = env_get("jh_clk");
	char *console = env_get("console");
	char *mmcroot = env_get("mmcroot");
	char *mmcdev = env_get("mmcdev");

	if (jh_clk) {
		if (*jh_clk != 0x20) {
			strcat(bootargs, jh_clk);
			strcat(bootargs, " ");
		}
	}

	if (console) {
		strcat(bootargs, "console=");
		strcat(bootargs, console);
		strcat(bootargs, " ");
	}

	if (mmcroot) {
		strcat(bootargs, "root=");
		strcat(bootargs, mmcroot);
		strcat(bootargs, " ");
	}

	if (mmcdev) {
		if (!strcmp(mmcdev, "0"))
			strcat(bootargs, "misc=/dev/mmcblk0p2 ");
		else if (!strcmp(mmcdev, "1"))
			strcat(bootargs, "misc=/dev/mmcblk1p2 ");
	}
}

static void parse_cmdline(void)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr, *file_size, *mmcdev;
	static char *fs_argv[5];

	int valid = 0;

	mmcdev = env_get("mmcdev");
	if (!mmcdev) {
		printf("Can't get mmcdev, default use eMMC\n");
		mmcdev = "0";
	}

	file_addr = env_get("cmdline_addr");
	if (!file_addr) {
		printf("Can't get cmdline_addr address\n");
		file_addr = "0x900000";
	}

	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr)
		printf("Can't set addr\n");

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";

	if (!strcmp(mmcdev, "0"))
		fs_argv[2] = "0:3";
	else if (!strcmp(mmcdev, "1"))
		fs_argv[2] = "1:3";
	else {
		printf("Invalid mmcdev\n");
		goto end;
	}

	fs_argv[3] = file_addr;
	fs_argv[4] = "boot/cmdline.txt";

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[cmdline] do_ext2load fail\n");
		goto end;
	}

	file_size = env_get("filesize");
	size = simple_strtoul(file_size, NULL, 16);
	if (!size) {
		printf("[cmdline] Can't get filesize\n");
		goto end;
	}

	valid = 1;
	printf("cmdline.txt size = %lu\n", size);

	*((char *)addr + size) = 0x00;

	while(offset != size)
	{
		count = hw_skip_comment((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = hw_skip_line((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
		count = get_append((char *)(addr + offset));
		if(count > 0) {
			offset = offset + count;
			continue;
		}
	}

end:
	printf("cmdline.txt valid = %d\n", valid);
}

/* Stored value of bootdelay, used by autoboot_command() */
static int stored_bootdelay;

#if defined(CONFIG_AUTOBOOT_KEYED)
#if defined(CONFIG_AUTOBOOT_STOP_STR_SHA256)

/*
 * Use a "constant-length" time compare function for this
 * hash compare:
 *
 * https://crackstation.net/hashing-security.htm
 */
static int slow_equals(u8 *a, u8 *b, int len)
{
	int diff = 0;
	int i;

	for (i = 0; i < len; i++)
		diff |= a[i] ^ b[i];

	return diff == 0;
}

static int passwd_abort(uint64_t etime)
{
	const char *sha_env_str = env_get("bootstopkeysha256");
	u8 sha_env[SHA256_SUM_LEN];
	u8 sha[SHA256_SUM_LEN];
	char presskey[MAX_DELAY_STOP_STR];
	const char *algo_name = "sha256";
	u_int presskey_len = 0;
	int abort = 0;
	int size = sizeof(sha);
	int ret;

	if (sha_env_str == NULL)
		sha_env_str = CONFIG_AUTOBOOT_STOP_STR_SHA256;

	/*
	 * Generate the binary value from the environment hash value
	 * so that we can compare this value with the computed hash
	 * from the user input
	 */
	ret = hash_parse_string(algo_name, sha_env_str, sha_env);
	if (ret) {
		printf("Hash %s not supported!\n", algo_name);
		return 0;
	}

	/*
	 * We don't know how long the stop-string is, so we need to
	 * generate the sha256 hash upon each input character and
	 * compare the value with the one saved in the environment
	 */
	do {
		if (tstc()) {
			/* Check for input string overflow */
			if (presskey_len >= MAX_DELAY_STOP_STR)
				return 0;

			presskey[presskey_len++] = getc();

			/* Calculate sha256 upon each new char */
			hash_block(algo_name, (const void *)presskey,
				   presskey_len, sha, &size);

			/* And check if sha matches saved value in env */
			if (slow_equals(sha, sha_env, SHA256_SUM_LEN))
				abort = 1;
		}
	} while (!abort && get_ticks() <= etime);

	return abort;
}
#else
static int passwd_abort(uint64_t etime)
{
	int abort = 0;
	struct {
		char *str;
		u_int len;
		int retry;
	}
	delaykey[] = {
		{ .str = env_get("bootdelaykey"),  .retry = 1 },
		{ .str = env_get("bootstopkey"),   .retry = 0 },
	};

	char presskey[MAX_DELAY_STOP_STR];
	u_int presskey_len = 0;
	u_int presskey_max = 0;
	u_int i;

#  ifdef CONFIG_AUTOBOOT_DELAY_STR
	if (delaykey[0].str == NULL)
		delaykey[0].str = CONFIG_AUTOBOOT_DELAY_STR;
#  endif
#  ifdef CONFIG_AUTOBOOT_STOP_STR
	if (delaykey[1].str == NULL)
		delaykey[1].str = CONFIG_AUTOBOOT_STOP_STR;
#  endif

	for (i = 0; i < sizeof(delaykey) / sizeof(delaykey[0]); i++) {
		delaykey[i].len = delaykey[i].str == NULL ?
				    0 : strlen(delaykey[i].str);
		delaykey[i].len = delaykey[i].len > MAX_DELAY_STOP_STR ?
				    MAX_DELAY_STOP_STR : delaykey[i].len;

		presskey_max = presskey_max > delaykey[i].len ?
				    presskey_max : delaykey[i].len;

		debug_bootkeys("%s key:<%s>\n",
			       delaykey[i].retry ? "delay" : "stop",
			       delaykey[i].str ? delaykey[i].str : "NULL");
	}

	/* In order to keep up with incoming data, check timeout only
	 * when catch up.
	 */
	do {
		if (tstc()) {
			if (presskey_len < presskey_max) {
				presskey[presskey_len++] = getc();
			} else {
				for (i = 0; i < presskey_max - 1; i++)
					presskey[i] = presskey[i + 1];

				presskey[i] = getc();
			}
		}

		for (i = 0; i < sizeof(delaykey) / sizeof(delaykey[0]); i++) {
			if (delaykey[i].len > 0 &&
			    presskey_len >= delaykey[i].len &&
				memcmp(presskey + presskey_len -
					delaykey[i].len, delaykey[i].str,
					delaykey[i].len) == 0) {
					debug_bootkeys("got %skey\n",
						delaykey[i].retry ? "delay" :
						"stop");

				/* don't retry auto boot */
				if (!delaykey[i].retry)
					bootretry_dont_retry();
				abort = 1;
			}
		}
	} while (!abort && get_ticks() <= etime);

	return abort;
}
#endif

/***************************************************************************
 * Watch for 'delay' seconds for autoboot stop or autoboot delay string.
 * returns: 0 -  no key string, allow autoboot 1 - got key string, abort
 */
static int __abortboot(int bootdelay)
{
	int abort;
	uint64_t etime = endtick(bootdelay);

#  ifdef CONFIG_AUTOBOOT_PROMPT
	/*
	 * CONFIG_AUTOBOOT_PROMPT includes the %d for all boards.
	 * To print the bootdelay value upon bootup.
	 */
	printf(CONFIG_AUTOBOOT_PROMPT, bootdelay);
#  endif

	abort = passwd_abort(etime);
	if (!abort)
		debug_bootkeys("key timeout\n");

	return abort;
}

# else	/* !defined(CONFIG_AUTOBOOT_KEYED) */

#ifdef CONFIG_MENUKEY
static int menukey;
#endif

static int __abortboot(int bootdelay)
{
	int abort = 0;
	unsigned long ts;

#ifdef CONFIG_MENUPROMPT
	printf(CONFIG_MENUPROMPT);
#else
	printf("Hit key to stop autoboot('CTRL+C'): %2d ", bootdelay);
#endif

	if (ctrlc()) {		/* we press ctrl+c	*/
		(void) getc();  /* consume input	*/
		puts("\b\b\b 0");
		abort = 1;	/* don't auto boot	*/
	}

	while ((bootdelay > 0) && (!abort)) {
		--bootdelay;
		/* delay 1000 ms */
		ts = get_timer(0);
		do {
			if (ctrlc()) {		/* we got a ctrl+c key press    */
				abort  = 1;	/* don't auto boot	*/
				bootdelay = 0;	/* no more delay	*/
# ifdef CONFIG_MENUKEY
				menukey = 0x03;	/* ctrl+c key code	*/
# endif
				break;
			}
			udelay(10000);
		} while (!abort && get_timer(ts) < 1000);

		printf("\b\b\b%2d ", bootdelay);
	}

	putc('\n');

	return abort;
}
# endif	/* CONFIG_AUTOBOOT_KEYED */

static int abortboot(int bootdelay)
{
	int abort = 0;

	run_command("mmc partconf-check 0 0 1 0", 0);

	if (bootdelay >= 0)
		abort = __abortboot(bootdelay);

#ifdef CONFIG_SILENT_CONSOLE
	if (abort)
		gd->flags &= ~GD_FLG_SILENT;
#endif

	return abort;
}

static void process_fdt_options(const void *blob)
{
#if defined(CONFIG_OF_CONTROL) && defined(CONFIG_SYS_TEXT_BASE)
	ulong addr;

	/* Add an env variable to point to a kernel payload, if available */
	addr = fdtdec_get_config_int(gd->fdt_blob, "kernel-offset", 0);
	if (addr)
		env_set_addr("kernaddr", (void *)(CONFIG_SYS_TEXT_BASE + addr));

	/* Add an env variable to point to a root disk, if available */
	addr = fdtdec_get_config_int(gd->fdt_blob, "rootdisk-offset", 0);
	if (addr)
		env_set_addr("rootaddr", (void *)(CONFIG_SYS_TEXT_BASE + addr));
#endif /* CONFIG_OF_CONTROL && CONFIG_SYS_TEXT_BASE */
}

const char *bootdelay_process(void)
{
	char *s;
	int bootdelay;
#ifdef CONFIG_BOOTCOUNT_LIMIT
	unsigned long bootcount = 0;
	unsigned long bootlimit = 0;
#endif /* CONFIG_BOOTCOUNT_LIMIT */

#ifdef CONFIG_BOOTCOUNT_LIMIT
	bootcount = bootcount_load();
	bootcount++;
	bootcount_store(bootcount);
	env_set_ulong("bootcount", bootcount);
	bootlimit = env_get_ulong("bootlimit", 10, 0);
#endif /* CONFIG_BOOTCOUNT_LIMIT */

	s = env_get("bootdelay");
	bootdelay = s ? (int)simple_strtol(s, NULL, 10) : CONFIG_BOOTDELAY;

#if defined(is_boot_from_usb)
	if (is_boot_from_usb() && env_get("bootcmd_mfg")) {
		disconnect_from_pc();
		printf("Boot from USB for mfgtools\n");
		bootdelay = 0;
		set_default_env("Use default environment for \
				 mfgtools\n");
	} else if (is_boot_from_usb()) {
		printf("Boot from USB for uuu\n");
		env_set("bootcmd", "fastboot 0");
	} else {
		printf("Normal Boot\n");
	}
#endif

#ifdef CONFIG_OF_CONTROL
	bootdelay = fdtdec_get_config_int(gd->fdt_blob, "bootdelay",
			bootdelay);
#endif

	debug("### main_loop entered: bootdelay=%d\n\n", bootdelay);

#if defined(CONFIG_MENU_SHOW)
	bootdelay = menu_show(bootdelay);
#endif
	bootretry_init_cmd_timeout();

#ifdef CONFIG_POST
	if (gd->flags & GD_FLG_POSTFAIL) {
		s = env_get("failbootcmd");
	} else
#endif /* CONFIG_POST */
#ifdef CONFIG_BOOTCOUNT_LIMIT
	if (bootlimit && (bootcount > bootlimit)) {
		printf("Warning: Bootlimit (%u) exceeded. Using altbootcmd.\n",
		       (unsigned)bootlimit);
		s = env_get("altbootcmd");
	} else
#endif /* CONFIG_BOOTCOUNT_LIMIT */
		s = env_get("bootcmd");

#if defined(is_boot_from_usb)
	if (is_boot_from_usb() && env_get("bootcmd_mfg")) {
		s = env_get("bootcmd_mfg");
		printf("Run bootcmd_mfg: %s\n", s);
	}
#endif

	process_fdt_options(gd->fdt_blob);
	stored_bootdelay = bootdelay;

	return s;
}

void autoboot_command(const char *s)
{
	debug("### main_loop: bootcmd=\"%s\"\n", s ? s : "<UNDEFINED>");

	gpio_request(GPIO5_IO04, "EEPROM_WRITE_CONTROL");
	gpio_direction_output(GPIO5_IO04, 1);

	set_bootargs();
	parse_cmdline();
	printf("bootargs: %s\n", bootargs);
	env_set("bootargs", bootargs);

	if (stored_bootdelay != -1 && s && !abortboot(stored_bootdelay)) {
#if defined(CONFIG_AUTOBOOT_KEYED) && !defined(CONFIG_AUTOBOOT_KEYED_CTRLC)
		int prev = disable_ctrlc(1);	/* disable Control C checking */
#endif

		run_command_list(s, -1, 0);

#if defined(CONFIG_AUTOBOOT_KEYED) && !defined(CONFIG_AUTOBOOT_KEYED_CTRLC)
		disable_ctrlc(prev);	/* restore Control C checking */
#endif
	}

#ifdef CONFIG_MENUKEY
	if (menukey == CONFIG_MENUKEY) {
		s = env_get("menucmd");
		if (s)
			run_command_list(s, -1, 0);
	}
#endif /* CONFIG_MENUKEY */
}
