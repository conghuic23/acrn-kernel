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

#ifndef SHARED_BUF_H
#define SHARED_BUF_H

#include <asm/acrn.h>
#include "acrn_drv.h"

void *acrn_sbuf_get_data_ptr(shared_buf_t *sbuf);
void acrn_sbuf_move_next(struct shared_buf *sbuf);
#endif /* SHARED_BUF_H */
