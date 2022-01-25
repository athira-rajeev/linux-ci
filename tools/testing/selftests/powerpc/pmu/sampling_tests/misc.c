// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2022, Athira Rajeev, IBM Corp.
 * Copyright 2022, Madhavan Srinivasan, IBM Corp.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <ctype.h>

#include "misc.h"

#define PAGE_SIZE               sysconf(_SC_PAGESIZE)

/* Storage for platform version */
int pvr, pvr_dd;
u64 platform_extended_mask;
int pSeries;

/* Mask and Shift for Event code fields */
int ev_mask_pmcxsel, ev_shift_pmcxsel;		//pmcxsel field
int ev_mask_marked, ev_shift_marked;		//marked filed
int ev_mask_comb, ev_shift_comb;		//combine field
int ev_mask_unit, ev_shift_unit;		//unit field
int ev_mask_pmc, ev_shift_pmc;			//pmc field
int ev_mask_cache, ev_shift_cache;		//Cache sel field
int ev_mask_sample, ev_shift_sample;		//Random sampling field
int ev_mask_thd_sel, ev_shift_thd_sel;		//thresh_sel field
int ev_mask_thd_start, ev_shift_thd_start;	//thresh_start field
int ev_mask_thd_stop, ev_shift_thd_stop;	//thresh_stop field
int ev_mask_thd_cmp, ev_shift_thd_cmp;		//thresh cmp field
int ev_mask_sm, ev_shift_sm;			//SDAR mode field
int ev_mask_rsq, ev_shift_rsq;			//radix scope qual field
int ev_mask_l2l3, ev_shift_l2l3;		//l2l3 sel field
int ev_mask_mmcr3_src, ev_shift_mmcr3_src;	//mmcr3 field

static void init_ev_encodes(void)
{
	ev_mask_pmcxsel = 0xff;
	ev_shift_pmcxsel = 0;
	ev_mask_marked = 1;
	ev_shift_marked = 8;
	ev_mask_unit = 0xf;
	ev_shift_unit = 12;
	ev_mask_pmc = 0xf;
	ev_shift_pmc = 16;
	ev_mask_sample	= 0x1f;
	ev_shift_sample = 24;
	ev_mask_thd_sel = 0x7;
	ev_shift_thd_sel = 29;
	ev_mask_thd_start = 0xf;
	ev_shift_thd_start = 36;
	ev_mask_thd_stop = 0xf;
	ev_shift_thd_stop = 32;

	switch (pvr) {
	case POWER10:
		ev_mask_rsq = 1;
		ev_shift_rsq = 9;
		ev_mask_comb = 3;
		ev_shift_comb = 10;
		ev_mask_cache = 3;
		ev_shift_cache = 20;
		ev_mask_sm = 0x3;
		ev_shift_sm = 22;
		ev_mask_l2l3 = 0x1f;
		ev_shift_l2l3 = 40;
		ev_mask_mmcr3_src = 0x7fff;
		ev_shift_mmcr3_src = 45;
		break;
	case POWER9:
		ev_mask_comb = 3;
		ev_shift_comb = 10;
		ev_mask_cache = 0xf;
		ev_shift_cache = 20;
		ev_mask_thd_cmp = 0x3ff;
		ev_shift_thd_cmp = 40;
		ev_mask_sm = 0x3;
		ev_shift_sm = 50;
		break;
	default:
		FAIL_IF_EXIT(1);
	}
}

static int __get_pvr(int flg)
{
	FILE *fd;
	char *buf = NULL, *search_string = "revision", tmp[4];
	size_t len = 0;
	int ret = -1;

	fd = fopen("/proc/cpuinfo", "r");
	if (!fd)
		return -1;

	/* get to the line that matters */
	while (getline(&buf, &len, fd) > 0) {
		ret = strncmp(buf, search_string, strlen(search_string));
		if (!ret)
			break;
	}

	switch (flg) {
	case 1: /* get processor version number */
		/* seek to pvr hex values within the line */
		while (*buf++ != '(')
			; /* nothing to run */
		buf += 5;
		strncpy(tmp, buf, 3);

		fclose(fd);
		return strtol(tmp, NULL, 16);

	case 2: /* get processor major revision number */
		/* seek to pvr hex values within the line */
		while (*buf++ != ':')
			; /* nothing to run */
		strncpy(tmp, buf, 3);

		fclose(fd);
		return (int)strtof(tmp, NULL);
	default:
		return -1;
	}
}

static int init_platform(void)
{
	FILE *fd;
	char *buf = NULL, *search_string = "pSeries", *sim = "Mambo", *ptr;
	size_t len = 0;

	fd = fopen("/proc/cpuinfo", "r");
	if (!fd)
		return -1;

	/* check for sim (like mambo) */
	while (getline(&buf, &len, fd) > 0) {
		ptr = strstr(buf, sim);
		if (ptr)
			return -1;
	}

	fseek(fd, 0, SEEK_SET);

	/* get to the line that matters */
	while (getline(&buf, &len, fd) > 0) {
		ptr = strstr(buf, search_string);
		if (ptr) {
			pSeries = 1;
			break;
		}
	}

	fclose(fd);
	return 0;
}

static int get_ver(void)
{
	return __get_pvr(1);
}

static int get_rev_maj(void)
{
	return __get_pvr(2);
}

/* Return the extended regs mask value */
static u64 perf_get_platform_reg_mask(void)
{
	if (have_hwcap2(PPC_FEATURE2_ARCH_3_1))
		return PERF_POWER10_MASK;
	return PERF_POWER9_MASK;
}

int check_extended_regs_support(void)
{
	int fd;
	struct event event;

	event_init(&event, 0x1001e);

	event.attr.type = 4;
	event.attr.sample_period = 1;
	event.attr.disabled = 1;
	event.attr.sample_type = PERF_SAMPLE_REGS_INTR;
	event.attr.sample_regs_intr = platform_extended_mask;

	fd = event_open(&event);
	if (fd != -1)
		return 0;

	return -1;
}

int check_pvr_for_sampling_tests(void)
{
	pvr = get_ver();
	/* Exit if it fails to fetch pvr */
	if (pvr < 0) {
		printf("%s: Failed to fetch pvr\n", __func__);
		FAIL_IF_EXIT(1);
	}

	platform_extended_mask = perf_get_platform_reg_mask();

	/*
	 * Check for supported platforms
	 * for sampling test
	 */
	if ((pvr != POWER10) && (pvr != POWER9))
		goto out;

	/*
	 * Check PMU driver registered by looking for
	 * PPC_FEATURE2_EBB bit in AT_HWCAP2
	 */
	if (!have_hwcap2(PPC_FEATURE2_EBB))
		goto out;

	/* check if platform supports extended regs */
	if (check_extended_regs_support())
		goto out;

	pvr_dd = get_rev_maj();

	if (init_platform())
		goto out;

	init_ev_encodes();
	return 0;
out:
	printf("%s: Sampling tests un-supported\n", __func__);
	return -1;
}
/*
 * Allocate mmap buffer of "mmap_pages" number of
 * pages.
 */
void *event_sample_buf_mmap(int fd, int mmap_pages)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t mmap_size;
	void *buff;

	if (mmap_pages <= 0)
		return NULL;

	if (fd <= 0)
		return NULL;

	mmap_size =  page_size * (1 + mmap_pages);
	buff = mmap(NULL, mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (buff == MAP_FAILED) {
		perror("mmap() failed.");
		return NULL;
	}
	return buff;
}

/*
 * Post process the mmap buffer.
 * - If sample_count != NULL then return count of total
 *   number of samples present in the mmap buffer.
 * - If sample_count == NULL then return the address
 *   of first sample from the mmap buffer
 */
void *__event_read_samples(void *sample_buff, size_t *size, u64 *sample_count)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	struct perf_event_header *header = sample_buff + page_size;
	struct perf_event_mmap_page *metadata_page = sample_buff;
	unsigned long data_head, data_tail;

	/*
	 * PERF_RECORD_SAMPLE:
	 * struct {
	 *     struct perf_event_header hdr;
	 *     u64 data[];
	 * };
	 */

	data_head = metadata_page->data_head;
	/* sync memory before reading sample */
	mb();
	data_tail = metadata_page->data_tail;

	/* Check for sample_count */
	if (sample_count)
		*sample_count = 0;

	while (1) {
		/*
		 * Reads the mmap data buffer by moving
		 * the data_tail to know the last read data.
		 * data_head points to head in data buffer.
		 * refer "struct perf_event_mmap_page" in
		 * "include/uapi/linux/perf_event.h".
		 */
		if (data_head - data_tail < sizeof(header))
			return NULL;

		data_tail += sizeof(header);
		if (header->type == PERF_RECORD_SAMPLE) {
			*size = (header->size - sizeof(header));
			if (!sample_count)
				return sample_buff + page_size + data_tail;
			data_tail += *size;
			*sample_count += 1;
		} else {
			*size = (header->size - sizeof(header));
			if ((metadata_page->data_tail + *size) > metadata_page->data_head)
				data_tail = metadata_page->data_head;
			else
				data_tail += *size;
		}
		header = (struct perf_event_header *)((void *)header + header->size);
	}
	return NULL;
}
