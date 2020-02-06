/*
 * Copyright (c) 2013, Google Inc.
 *
 * (C) Copyright 2008 Semihalf
 *
 * (C) Copyright 2000-2006
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * Copyright (C) 2015-2016 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <fdt_support.h>
#include <errno.h>
#include <image.h>
#include <linux/libfdt.h>
#include <mapmem.h>
#include <asm/io.h>

#ifndef CONFIG_SYS_FDT_PAD
#define CONFIG_SYS_FDT_PAD 0x3000
#endif

DECLARE_GLOBAL_DATA_PTR;

static void fdt_error(const char *msg)
{
	puts("ERROR: ");
	puts(msg);
	puts(" - must RESET the board to recover.\n");
}

#define MAX_OVERLAY_NAME_LENGTH 128
struct hw_config
{
	int valid;

	int fec1;

	int overlay_count;
	char **overlay_file;
};

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

static unsigned long get_conf_value(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if (memcmp(text, "eth_wakeup=", 11) == 0) {
		i = 11;
		if(memcmp(text + i, "on", 2) == 0) {
			hw_conf->fec1 = 1;
			i = i + 2;
		} else if(memcmp(text + i, "off", 3) == 0) {
			hw_conf->fec1 = -1;
			i = i + 3;
		} else
			goto invalid_line;

	} else
		goto invalid_line;

	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
	}

invalid_line:
	//It's not a legal line, skip it.
	//printf("get_value: illegal line\n");
	while(*(text + i) != 0x00)
	{
		if(*(text + (i++)) == 0x0a)
			break;
	}
	return i;
}

static int set_file_conf(char *text, struct hw_config *hw_conf, int start_point, int file_ptr)
{
	char *ptr;
	int name_length;

	name_length = file_ptr - start_point;

	if(name_length && name_length < MAX_OVERLAY_NAME_LENGTH) {
		ptr = (char*)calloc(MAX_OVERLAY_NAME_LENGTH, sizeof(char));
		memcpy(ptr, text + start_point, name_length);
		ptr[name_length] = 0x00;
		hw_conf->overlay_file[hw_conf->overlay_count] = ptr;
		hw_conf->overlay_count += 1;

		//Pass a space for next string.
		start_point = file_ptr + 1;
	}

	return start_point;
}

static unsigned long get_overlay(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	int start_point = 0;
	int name_length;

	hw_conf->overlay_count = 0;
	while(*(text + i) != 0x00)
	{
		if(*(text + i) == 0x20)
			start_point = set_file_conf(text, hw_conf, start_point, i);

		if(*(text + i) == 0x0a)
			break;
		i++;
	}

	start_point = set_file_conf(text, hw_conf, start_point, i);

	return i;
}

static unsigned long hw_parse_property(char *text, struct hw_config *hw_conf)
{
	int i = 0;
	if(memcmp(text, "conf:",  5) == 0) {
		i = 5;
		i = i + get_conf_value(text + i, hw_conf);
	} else if(memcmp(text, "overlay=",  8) == 0) {
		i = 8;
		i = i + get_overlay(text + i, hw_conf);
	} else {
		printf("[conf] hw_parse_property: illegal line\n");
		//It's not a legal line, skip it.
		while(*(text + i) != 0x00) {
			if(*(text + (i++)) == 0x0a)
				break;
		}
	}
	return i;
}

static void parse_hw_config(struct hw_config *hw_conf)
{
	unsigned long count, offset = 0, addr, size;
	char *file_addr, *file_size;
	static char *fs_argv[5];

	int valid = 0;

	file_addr = env_get("conf_addr");
	if (!file_addr) {
		printf("Can't get conf_addr address\n");
		file_addr = "0x800000";
	}

	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr)
		printf("Can't set addr\n");

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";
	fs_argv[2] = "0:2";
	fs_argv[3] = file_addr;
	fs_argv[4] = "boot/config.txt";

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[conf] do_ext2load fail\n");
		goto end;
	}

	file_size = env_get("filesize");
	size = simple_strtoul(file_size, NULL, 16);
	if (!size) {
		printf("[conf] Can't get filesize\n");
		goto end;
	}

	valid = 1;
	printf("hw_conf size = %lu\n", size);

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
		count = hw_parse_property((char *)(addr + offset), hw_conf);
		if(count > 0) {
			offset = offset + count;
			continue;
		}
	}
end:
	hw_conf->valid = valid;
}

static int set_hw_property(struct fdt_header *working_fdt, char *path, char *property, char *value, int length)
{
	int offset;
	int ret;

	printf("set_hw_property: %s %s %s\n", path, property, value);
	offset = fdt_path_offset (working_fdt, path);
	if (offset < 0) {
		printf("libfdt fdt_path_offset() returned %s\n", fdt_strerror(offset));
		return -1;
	}
	ret = fdt_setprop(working_fdt, offset, property, value, length);
	if (ret < 0) {
		printf("libfdt fdt_setprop(): %s\n", fdt_strerror(ret));
		return -1;
	}

	return 0;
}

static struct fdt_header *resize_working_fdt(void)
{
	struct fdt_header *working_fdt;
	unsigned long addr;
	char *file_addr;

	int err;

	file_addr = env_get("fdt_addr");
	if (!file_addr) {
		printf("Can't get fdt address, set default\n");
		file_addr = "0x43000000";
	}
	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr) {
		printf("Can't get fdt address\n");
		return NULL;
	}

	working_fdt = map_sysmem(addr, 0);
	err = fdt_open_into(working_fdt, working_fdt, (1024 * 1024));
	if (err != 0) {
		printf("libfdt fdt_open_into(): %s\n", fdt_strerror(err));
		return NULL;
	}

	printf("fdt magic number %x\n", working_fdt->magic);
	printf("fdt size %u\n", fdt_totalsize(working_fdt));

	return working_fdt;
}

#ifdef CONFIG_OF_LIBFDT_OVERLAY
static int fdt_valid(struct fdt_header **blobp)
{
	const void *blob = *blobp;
	int err;

	if (blob == NULL) {
		printf ("The address of the fdt is invalid (NULL).\n");
		return 0;
	}

	err = fdt_check_header(blob);
	if (err == 0)
		return 1;	/* valid */

	if (err < 0) {
		printf("libfdt fdt_check_header(): %s", fdt_strerror(err));
		/*
		 * Be more informative on bad version.
		 */
		if (err == -FDT_ERR_BADVERSION) {
			if (fdt_version(blob) < FDT_FIRST_SUPPORTED_VERSION)
				printf (" - too old, fdt %d < %d", fdt_version(blob), FDT_FIRST_SUPPORTED_VERSION);
			if (fdt_last_comp_version(blob) > FDT_LAST_SUPPORTED_VERSION)
				printf (" - too new, fdt %d > %d", fdt_version(blob), FDT_LAST_SUPPORTED_VERSION);
		}
		printf("\n");
		*blobp = NULL;
		return 0;
	}
	return 1;
}

static int merge_dts_overlay(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, char *overlay_name)
{
	unsigned long addr;
	char *file_addr;
	struct fdt_header *blob;
	int ret;
	char overlay_file[] = "boot/overlays/";

	static char *fs_argv[5];

	file_addr = env_get("fdt_overlay_addr");
	if (!file_addr) {
		printf("Can't get fdt overlay, set default\n");
		file_addr = "0x42000000";
	}
	addr = simple_strtoul(file_addr, NULL, 16);
	if (!addr) {
		printf("Can't get fdt overlay\n");
		goto fail;
	}

	strcat(overlay_file, overlay_name);
	strncat(overlay_file, ".dtbo", 6);

	fs_argv[0] = "ext2load";
	fs_argv[1] = "mmc";
	fs_argv[2] = "0:2";
	fs_argv[3] = file_addr;
	fs_argv[4] = overlay_file;

	if (do_ext2load(NULL, 0, 5, fs_argv)) {
		printf("[merge_dts_overlay] do_ext2load fail\n");
		goto fail;
	}

	blob = map_sysmem(addr, 0);
	if (!fdt_valid(&blob)) {
		printf("[merge_dts_overlay] fdt_valid is invalid\n");
		goto fail;
	} else
		printf("fdt_valid\n");

	ret = fdt_overlay_apply(working_fdt, blob);
	if (ret) {
		printf("[merge_dts_overlay] fdt_overlay_apply(): %s\n", fdt_strerror(ret));
		goto fail;
	}

	return 0;

fail:
	return -1;
}
#endif

static void handle_hw_conf(cmd_tbl_t *cmdtp, struct fdt_header *working_fdt, struct hw_config *hw_conf)
{
	if(working_fdt == NULL)
		return;

#ifdef CONFIG_OF_LIBFDT_OVERLAY
	int i;
	for (i = 0; i < hw_conf->overlay_count; i++) {
		if(merge_dts_overlay(cmdtp, working_fdt, hw_conf->overlay_file[i]) < 0)
			printf("Can't merge dts overlay: %s\n", hw_conf->overlay_file[i]);
		else
			printf("Merged dts overlay: %s\n", hw_conf->overlay_file[i]);

		free(hw_conf->overlay_file[i]);
	}
#endif

	if (hw_conf->fec1 == 1)
		set_hw_property(working_fdt, "/ethernet@30be0000", "wakeup-enable", "1", 2);
	else if (hw_conf->fec1 == -1)
		set_hw_property(working_fdt, "/ethernet@30be0000", "wakeup-enable", "0", 2);

}

#if defined(CONFIG_IMAGE_FORMAT_LEGACY)
static const image_header_t *image_get_fdt(ulong fdt_addr)
{
	const image_header_t *fdt_hdr = map_sysmem(fdt_addr, 0);

	image_print_contents(fdt_hdr);

	puts("   Verifying Checksum ... ");
	if (!image_check_hcrc(fdt_hdr)) {
		fdt_error("fdt header checksum invalid");
		return NULL;
	}

	if (!image_check_dcrc(fdt_hdr)) {
		fdt_error("fdt checksum invalid");
		return NULL;
	}
	puts("OK\n");

	if (!image_check_type(fdt_hdr, IH_TYPE_FLATDT)) {
		fdt_error("uImage is not a fdt");
		return NULL;
	}
	if (image_get_comp(fdt_hdr) != IH_COMP_NONE) {
		fdt_error("uImage is compressed");
		return NULL;
	}
	if (fdt_check_header((void *)image_get_data(fdt_hdr)) != 0) {
		fdt_error("uImage data is not a fdt");
		return NULL;
	}
	return fdt_hdr;
}
#endif

/**
 * boot_fdt_add_mem_rsv_regions - Mark the memreserve sections as unusable
 * @lmb: pointer to lmb handle, will be used for memory mgmt
 * @fdt_blob: pointer to fdt blob base address
 *
 * Adds the memreserve regions in the dtb to the lmb block.  Adding the
 * memreserve regions prevents u-boot from using them to store the initrd
 * or the fdt blob.
 */
void boot_fdt_add_mem_rsv_regions(struct lmb *lmb, void *fdt_blob)
{
	uint64_t addr, size;
	int i, total;

	if (fdt_check_header(fdt_blob) != 0)
		return;

	total = fdt_num_mem_rsv(fdt_blob);
	for (i = 0; i < total; i++) {
		if (fdt_get_mem_rsv(fdt_blob, i, &addr, &size) != 0)
			continue;
		printf("   reserving fdt memory region: addr=%llx size=%llx\n",
		       (unsigned long long)addr, (unsigned long long)size);
		lmb_reserve(lmb, addr, size);
	}
}

/**
 * boot_relocate_fdt - relocate flat device tree
 * @lmb: pointer to lmb handle, will be used for memory mgmt
 * @of_flat_tree: pointer to a char* variable, will hold fdt start address
 * @of_size: pointer to a ulong variable, will hold fdt length
 *
 * boot_relocate_fdt() allocates a region of memory within the bootmap and
 * relocates the of_flat_tree into that region, even if the fdt is already in
 * the bootmap.  It also expands the size of the fdt by CONFIG_SYS_FDT_PAD
 * bytes.
 *
 * of_flat_tree and of_size are set to final (after relocation) values
 *
 * returns:
 *      0 - success
 *      1 - failure
 */
int boot_relocate_fdt(struct lmb *lmb, char **of_flat_tree, ulong *of_size)
{
	void	*fdt_blob = *of_flat_tree;
	void	*of_start = NULL;
	char	*fdt_high;
	ulong	of_len = 0;
	int	err;
	int	disable_relocation = 0;

	struct fdt_header *working_fdt;
	struct hw_config hw_conf;
	memset(&hw_conf, 0, sizeof(struct hw_config));
	parse_hw_config(&hw_conf);

	printf("config.txt valid = %d\n", hw_conf.valid);
	if(hw_conf.valid == 1) {
		printf("config on: 1, config off: -1, no config: 0\n");
		printf("conf.eth_wakeup = %d\n", hw_conf.fec1);

		for (int i = 0; i < hw_conf.overlay_count; i++)
			printf("get overlay name: %s\n", hw_conf.overlay_file[i]);
	}

	/* nothing to do */
	if (*of_size == 0)
		return 0;

	if (fdt_check_header(fdt_blob) != 0) {
		fdt_error("image is not a fdt");
		goto error;
	}

	/* position on a 4K boundary before the alloc_current */
	/* Pad the FDT by a specified amount */
	of_len = *of_size + CONFIG_SYS_FDT_PAD;

	/* If fdt_high is set use it to select the relocation address */
	fdt_high = env_get("fdt_high");
	if (fdt_high) {
		void *desired_addr = (void *)simple_strtoul(fdt_high, NULL, 16);

		if (((ulong) desired_addr) == ~0UL) {
			/* All ones means use fdt in place */
			of_start = fdt_blob;
			lmb_reserve(lmb, (ulong)of_start, of_len);
			disable_relocation = 1;
		} else if (desired_addr) {
			of_start =
			    (void *)(ulong) lmb_alloc_base(lmb, of_len, 0x1000,
							   (ulong)desired_addr);
			if (of_start == NULL) {
				puts("Failed using fdt_high value for Device Tree");
				goto error;
			}
		} else {
			of_start =
			    (void *)(ulong) lmb_alloc(lmb, of_len, 0x1000);
		}
	} else {
		of_start =
		    (void *)(ulong) lmb_alloc_base(lmb, of_len, 0x1000,
						   env_get_bootm_mapsize()
						   + env_get_bootm_low());
	}

	if (of_start == NULL) {
		puts("device tree - allocation error\n");
		goto error;
	}

	if (disable_relocation) {
		/*
		 * We assume there is space after the existing fdt to use
		 * for padding
		 */
		fdt_set_totalsize(of_start, of_len);
		printf("   Using Device Tree in place at %p, end %p\n",
		       of_start, of_start + of_len - 1);
	} else {
		debug("## device tree at %p ... %p (len=%ld [0x%lX])\n",
		      fdt_blob, fdt_blob + *of_size - 1, of_len, of_len);

		printf("   Loading Device Tree to %p, end %p ... ",
		       of_start, of_start + of_len - 1);

		err = fdt_open_into(fdt_blob, of_start, of_len);
		if (err != 0) {
			fdt_error("fdt move failed");
			goto error;
		}
		puts("OK\n");
	}

	*of_flat_tree = of_start;
	*of_size = of_len;

	set_working_fdt_addr((ulong)*of_flat_tree);

	working_fdt = resize_working_fdt();
	if(working_fdt != NULL) {
		if(hw_conf.valid)
			handle_hw_conf(NULL, working_fdt, &hw_conf);
	}

	return 0;

error:
	return 1;
}

/**
 * boot_get_fdt - main fdt handling routine
 * @argc: command argument count
 * @argv: command argument list
 * @arch: architecture (IH_ARCH_...)
 * @images: pointer to the bootm images structure
 * @of_flat_tree: pointer to a char* variable, will hold fdt start address
 * @of_size: pointer to a ulong variable, will hold fdt length
 *
 * boot_get_fdt() is responsible for finding a valid flat device tree image.
 * Curently supported are the following ramdisk sources:
 *      - multicomponent kernel/ramdisk image,
 *      - commandline provided address of decicated ramdisk image.
 *
 * returns:
 *     0, if fdt image was found and valid, or skipped
 *     of_flat_tree and of_size are set to fdt start address and length if
 *     fdt image is found and valid
 *
 *     1, if fdt image is found but corrupted
 *     of_flat_tree and of_size are set to 0 if no fdt exists
 */
int boot_get_fdt(int flag, int argc, char * const argv[], uint8_t arch,
		bootm_headers_t *images, char **of_flat_tree, ulong *of_size)
{
#if defined(CONFIG_IMAGE_FORMAT_LEGACY)
	const image_header_t *fdt_hdr;
	ulong		load, load_end;
	ulong		image_start, image_data, image_end;
#endif
	ulong		fdt_addr;
	char		*fdt_blob = NULL;
	void		*buf;
#if CONFIG_IS_ENABLED(FIT)
	const char	*fit_uname_config = images->fit_uname_cfg;
	const char	*fit_uname_fdt = NULL;
	ulong		default_addr;
	int		fdt_noffset;
#endif
	const char *select = NULL;
	int		ok_no_fdt = 0;

	*of_flat_tree = NULL;
	*of_size = 0;

	if (argc > 2)
		select = argv[2];
	if (select || genimg_has_config(images)) {
#if CONFIG_IS_ENABLED(FIT)
		if (select) {
			/*
			 * If the FDT blob comes from the FIT image and the
			 * FIT image address is omitted in the command line
			 * argument, try to use ramdisk or os FIT image
			 * address or default load address.
			 */
			if (images->fit_uname_rd)
				default_addr = (ulong)images->fit_hdr_rd;
			else if (images->fit_uname_os)
				default_addr = (ulong)images->fit_hdr_os;
			else
				default_addr = load_addr;

			if (fit_parse_conf(select, default_addr,
					   &fdt_addr, &fit_uname_config)) {
				debug("*  fdt: config '%s' from image at 0x%08lx\n",
				      fit_uname_config, fdt_addr);
			} else if (fit_parse_subimage(select, default_addr,
				   &fdt_addr, &fit_uname_fdt)) {
				debug("*  fdt: subimage '%s' from image at 0x%08lx\n",
				      fit_uname_fdt, fdt_addr);
			} else
#endif
			{
				fdt_addr = simple_strtoul(select, NULL, 16);
				debug("*  fdt: cmdline image address = 0x%08lx\n",
				      fdt_addr);
			}
#if CONFIG_IS_ENABLED(FIT)
		} else {
			/* use FIT configuration provided in first bootm
			 * command argument
			 */
			fdt_addr = map_to_sysmem(images->fit_hdr_os);
			fdt_noffset = fit_get_node_from_config(images,
							       FIT_FDT_PROP,
							       fdt_addr);
			if (fdt_noffset == -ENOENT)
				return 0;
			else if (fdt_noffset < 0)
				return 1;
		}
#endif
		debug("## Checking for 'FDT'/'FDT Image' at %08lx\n",
		      fdt_addr);

		/*
		 * Check if there is an FDT image at the
		 * address provided in the second bootm argument
		 * check image type, for FIT images get a FIT node.
		 */
		buf = map_sysmem(fdt_addr, 0);
		switch (genimg_get_format(buf)) {
#if defined(CONFIG_IMAGE_FORMAT_LEGACY)
		case IMAGE_FORMAT_LEGACY:
			/* verify fdt_addr points to a valid image header */
			printf("## Flattened Device Tree from Legacy Image at %08lx\n",
			       fdt_addr);
			fdt_hdr = image_get_fdt(fdt_addr);
			if (!fdt_hdr)
				goto no_fdt;

			/*
			 * move image data to the load address,
			 * make sure we don't overwrite initial image
			 */
			image_start = (ulong)fdt_hdr;
			image_data = (ulong)image_get_data(fdt_hdr);
			image_end = image_get_image_end(fdt_hdr);

			load = image_get_load(fdt_hdr);
			load_end = load + image_get_data_size(fdt_hdr);

			if (load == image_start ||
			    load == image_data) {
				fdt_addr = load;
				break;
			}

			if ((load < image_end) && (load_end > image_start)) {
				fdt_error("fdt overwritten");
				goto error;
			}

			debug("   Loading FDT from 0x%08lx to 0x%08lx\n",
			      image_data, load);

			memmove((void *)load,
				(void *)image_data,
				image_get_data_size(fdt_hdr));

			fdt_addr = load;
			break;
#endif
		case IMAGE_FORMAT_FIT:
			/*
			 * This case will catch both: new uImage format
			 * (libfdt based) and raw FDT blob (also libfdt
			 * based).
			 */
#if CONFIG_IS_ENABLED(FIT)
			/* check FDT blob vs FIT blob */
			if (fit_check_format(buf)) {
				ulong load, len;

				fdt_noffset = boot_get_fdt_fit(images,
					fdt_addr, &fit_uname_fdt,
					&fit_uname_config,
					arch, &load, &len);

				images->fit_hdr_fdt = map_sysmem(fdt_addr, 0);
				images->fit_uname_fdt = fit_uname_fdt;
				images->fit_noffset_fdt = fdt_noffset;
				fdt_addr = load;

				break;
			} else
#endif
			{
				/*
				 * FDT blob
				 */
				debug("*  fdt: raw FDT blob\n");
				printf("## Flattened Device Tree blob at %08lx\n",
				       (long)fdt_addr);
			}
			break;
		default:
			puts("ERROR: Did not find a cmdline Flattened Device Tree\n");
			goto no_fdt;
		}

		printf("   Booting using the fdt blob at %#08lx\n", fdt_addr);
		fdt_blob = map_sysmem(fdt_addr, 0);
	} else if (images->legacy_hdr_valid &&
			image_check_type(&images->legacy_hdr_os_copy,
					 IH_TYPE_MULTI)) {
		ulong fdt_data, fdt_len;

		/*
		 * Now check if we have a legacy multi-component image,
		 * get second entry data start address and len.
		 */
		printf("## Flattened Device Tree from multi component Image at %08lX\n",
		       (ulong)images->legacy_hdr_os);

		image_multi_getimg(images->legacy_hdr_os, 2, &fdt_data,
				   &fdt_len);
		if (fdt_len) {
			fdt_blob = (char *)fdt_data;
			printf("   Booting using the fdt at 0x%p\n", fdt_blob);

			if (fdt_check_header(fdt_blob) != 0) {
				fdt_error("image is not a fdt");
				goto error;
			}

			if (fdt_totalsize(fdt_blob) != fdt_len) {
				fdt_error("fdt size != image size");
				goto error;
			}
		} else {
			debug("## No Flattened Device Tree\n");
			goto no_fdt;
		}
	}
#ifdef CONFIG_ANDROID_BOOT_IMAGE
	else if (genimg_get_format((void *)images->os.start) ==
		IMAGE_FORMAT_ANDROID) {
		ulong fdt_data, fdt_len;
		android_image_get_second((void *)images->os.start,
		 &fdt_data, &fdt_len);

		if (fdt_len) {
			fdt_blob = (char *)fdt_data;
			printf("   Booting using the fdt at 0x%p\n", fdt_blob);

			if (fdt_check_header(fdt_blob) != 0) {
				fdt_error("image is not a fdt");
				goto error;
			}

			if (fdt_totalsize(fdt_blob) != fdt_len) {
				fdt_error("fdt size != image size");
				goto error;
			}
		} else {
			debug("## No Flattened Device Tree\n");
			goto no_fdt;
		}
	}
#endif
	else {
		debug("## No Flattened Device Tree\n");
		goto no_fdt;
	}

	*of_flat_tree = fdt_blob;
	*of_size = fdt_totalsize(fdt_blob);
	debug("   of_flat_tree at 0x%08lx size 0x%08lx\n",
	      (ulong)*of_flat_tree, *of_size);

	return 0;

no_fdt:
	ok_no_fdt = 1;
error:
	*of_flat_tree = NULL;
	*of_size = 0;
	if (!select && ok_no_fdt) {
		debug("Continuing to boot without FDT\n");
		return 0;
	}
	return 1;
}

/*
 * Verify the device tree.
 *
 * This function is called after all device tree fix-ups have been enacted,
 * so that the final device tree can be verified.  The definition of "verified"
 * is up to the specific implementation.  However, it generally means that the
 * addresses of some of the devices in the device tree are compared with the
 * actual addresses at which U-Boot has placed them.
 *
 * Returns 1 on success, 0 on failure.  If 0 is returned, U-Boot will halt the
 * boot process.
 */
__weak int ft_verify_fdt(void *fdt)
{
	return 1;
}

__weak int arch_fixup_fdt(void *blob)
{
	return 0;
}

int image_setup_libfdt(bootm_headers_t *images, void *blob,
		       int of_size, struct lmb *lmb)
{
	ulong *initrd_start = &images->initrd_start;
	ulong *initrd_end = &images->initrd_end;
	int ret = -EPERM;
	int fdt_ret;

	if (fdt_root(blob) < 0) {
		printf("ERROR: root node setup failed\n");
		goto err;
	}
	if (fdt_chosen(blob) < 0) {
		printf("ERROR: /chosen node create failed\n");
		goto err;
	}
	if (arch_fixup_fdt(blob) < 0) {
		printf("ERROR: arch-specific fdt fixup failed\n");
		goto err;
	}
	/* Update ethernet nodes */
	fdt_fixup_ethernet(blob);
	if (IMAGE_OF_BOARD_SETUP) {
		fdt_ret = ft_board_setup(blob, gd->bd);
		if (fdt_ret) {
			printf("ERROR: board-specific fdt fixup failed: %s\n",
			       fdt_strerror(fdt_ret));
			goto err;
		}
	}
	if (IMAGE_OF_SYSTEM_SETUP) {
		fdt_ret = ft_system_setup(blob, gd->bd);
		if (fdt_ret) {
			printf("ERROR: system-specific fdt fixup failed: %s\n",
			       fdt_strerror(fdt_ret));
			goto err;
		}
	}

	/* Delete the old LMB reservation */
	if (lmb)
		lmb_free(lmb, (phys_addr_t)(u32)(uintptr_t)blob,
			 (phys_size_t)fdt_totalsize(blob));

	ret = fdt_shrink_to_minimum(blob, 0);
	if (ret < 0)
		goto err;
	of_size = ret;

	if (*initrd_start && *initrd_end) {
		of_size += FDT_RAMDISK_OVERHEAD;
		fdt_set_totalsize(blob, of_size);
	}
	/* Create a new LMB reservation */
	if (lmb)
		lmb_reserve(lmb, (ulong)blob, of_size);

	fdt_initrd(blob, *initrd_start, *initrd_end);
	if (!ft_verify_fdt(blob))
		goto err;

#if defined(CONFIG_SOC_KEYSTONE)
	if (IMAGE_OF_BOARD_SETUP)
		ft_board_setup_ex(blob, gd->bd);
#endif

	return 0;
err:
	printf(" - must RESET the board to recover.\n\n");

	return ret;
}
