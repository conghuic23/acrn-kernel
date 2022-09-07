// SPDX-License-Identifier: GPL-2.0
/*
 * ACRN shared buffer
 *
 * Copyright (c) 2022 Intel Corporation. All rights reserved.
 *
 * Authors:
 * 	Li Fei <fei1.li@intel.com>
 * 	Chen Conghui <conghui.chen@intel.com>
 */

#define pr_fmt(fmt) "SBuf: " fmt

#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/hypervisor.h>
#include <asm/acrn.h>

#include "acrn_drv.h"
#include "sbuf.h"
#include "hypercall.h"

static inline bool sbuf_is_empty(shared_buf_t *sbuf)
{
	return (sbuf->head == sbuf->tail);
}

static inline uint32_t sbuf_next_ptr(uint32_t pos,
		uint32_t span, uint32_t scope)
{
	pos += span;
	pos = (pos >= scope) ? (pos - scope) : pos;
	return pos;
}

void *acrn_sbuf_get_data_ptr(shared_buf_t *sbuf)
{
	if (sbuf_is_empty(sbuf))
		return NULL;

	return (void *)sbuf + SBUF_HEAD_SIZE + sbuf->head;
}

void acrn_sbuf_move_next(shared_buf_t *sbuf)
{
	sbuf->head = sbuf_next_ptr(sbuf->head, sbuf->ele_size, sbuf->size);
}
