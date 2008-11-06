/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_ERROR_H
#define __POLKIT_ERROR_H

#include <glib-object.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_ERROR (polkit_error_get_type ())

/**
 * POLKIT_ERROR:
 *
 * Error domain for PolicyKit. Errors in this domain will be from the
 * #PolkitErrorEnum enumeration.  See #GError for more information on
 * error domains.
 **/
#define POLKIT_ERROR polkit_error_quark()

GQuark polkit_error_quark    (void);
GType  polkit_error_get_type (void) G_GNUC_CONST;

/**
 * PolkitErrorEnum:
 * @POLKIT_ERROR_FAILED: The operation failed.
 * @POLKIT_ERROR_NOT_SUPPORTED: Operation not supported by backend.
 *
 * Error codes returned by PolicyKit functions.
 */
typedef enum {
        POLKIT_ERROR_FAILED,
        POLKIT_ERROR_NOT_SUPPORTED,
        POLKIT_ERROR_NUM_ERRORS
} PolkitErrorEnum;

G_END_DECLS

#endif /* __POLKIT_ERROR_H */

