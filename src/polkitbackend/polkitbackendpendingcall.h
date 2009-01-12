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

#if !defined (_POLKIT_BACKEND_COMPILATION) && !defined(_POLKIT_BACKEND_INSIDE_POLKIT_BACKEND_H)
#error "Only <polkitbackend/polkitbackend.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_BACKEND_PENDING_CALL_H
#define __POLKIT_BACKEND_PENDING_CALL_H

#include <glib-object.h>
#include "polkitbackendtypes.h"

G_BEGIN_DECLS

#define POLKIT_BACKEND_TYPE_PENDING_CALL         (polkit_backend_pending_call_get_type ())
#define POLKIT_BACKEND_PENDING_CALL(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_BACKEND_TYPE_PENDING_CALL, PolkitBackendPendingCall))
#define POLKIT_BACKEND_PENDING_CALL_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_BACKEND_TYPE_PENDING_CALL, PolkitBackendPendingCallClass))
#define POLKIT_BACKEND_PENDING_CALL_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_BACKEND_TYPE_PENDING_CALL,PolkitBackendPendingCallClass))
#define POLKIT_BACKEND_IS_PENDING_CALL(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_BACKEND_TYPE_PENDING_CALL))
#define POLKIT_BACKEND_IS_PENDING_CALL_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_BACKEND_TYPE_PENDING_CALL))

#if 0
typedef struct _PolkitBackendPendingCall         PolkitBackendPendingCall;
#endif
typedef struct _PolkitBackendPendingCallClass    PolkitBackendPendingCallClass;

struct _PolkitBackendPendingCall
{
  GObject parent_instance;
};

struct _PolkitBackendPendingCallClass
{
  GObjectClass parent_class;

  /*< public >*/

  /*< private >*/
  /* Padding for future expansion */
  void (*_polkit_reserved1) (void);
  void (*_polkit_reserved2) (void);
  void (*_polkit_reserved3) (void);
  void (*_polkit_reserved4) (void);
  void (*_polkit_reserved5) (void);
  void (*_polkit_reserved6) (void);
  void (*_polkit_reserved7) (void);
  void (*_polkit_reserved8) (void);
};

GType                 polkit_backend_pending_call_get_type     (void) G_GNUC_CONST;
PolkitSubject        *polkit_backend_pending_call_get_caller   (PolkitBackendPendingCall *pending_call);
PolkitBackendServer  *polkit_backend_pending_call_get_server   (PolkitBackendPendingCall *pending_call);
void                  polkit_backend_pending_call_return_error (PolkitBackendPendingCall *pending_call,
                                                                GQuark                    domain,
                                                                gint                      code,
                                                                const gchar              *format,
                                                                ...);
void                  polkit_backend_pending_call_return_gerror (PolkitBackendPendingCall *pending_call,
                                                                 GError                   *error);



G_END_DECLS

#endif /* __POLKIT_BACKEND_PENDING_CALL_H */

