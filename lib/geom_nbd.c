/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <libgeom.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "core/geom.h"
#include "misc/subr.h"

#include "g_nbd.h"

uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_NBD_VERSION;

/*
 * Available commands:
 *
 * ...
 */
struct g_command class_commands[] = {
	/* ... */
	G_CMD_SENTINEL
};
