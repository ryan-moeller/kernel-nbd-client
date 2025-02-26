/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>

#include <geom/geom.h>

#include "g_nbd.h"

FEATURE(geom_nbd, "GEOM NBD module");

struct g_class g_nbd_class = {
	.name = G_NBD_CLASS_NAME,
	.version = G_VERSION,
	/* ... */
};

DECLARE_GEOM_CLASS(g_nbd_class, g_nbd);
MODULE_VERSION(geom_nbd, 0);
