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

#ifndef __POLKIT_SUBJECT_H__
#define __POLKIT_SUBJECT_H__

#include <glib-object.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_SUBJECT            (polkit_subject_get_type ())
#define POLKIT_SUBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), POLKIT_TYPE_SUBJECT, PolkitSubject))
#define POLKIT_IS_SUBJECT(obj)	 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), POLKIT_TYPE_SUBJECT))
#define POLKIT_SUBJECT_GET_IFACE(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), POLKIT_TYPE_SUBJECT, PolkitSubjectIface))

/**
 * PolkitSubject:
 *
 * An abstract type that specifies a subject.
 **/
typedef struct _PolkitSubject      PolkitSubject;
typedef struct _PolkitSubjectIface PolkitSubjectIface;

/**
 * PolkitSubjectIface:
 * @g_iface: The parent interface.
 * @equal: Checks if two #PolkitSubject<!-- -->s are equal.
 *
 * #PolkitSubjectIface is used to implement #PolkitSubject types for various
 * different subjects
 */
struct _PolkitSubjectIface
{
        GTypeInterface g_iface;

        /* Virtual Table */

        gboolean (* equal) (PolkitSubject *subject1,
                            PolkitSubject *subject2);
};

GType    polkit_subject_get_type  (void) G_GNUC_CONST;
gboolean polkit_subject_equal     (PolkitSubject  *subject1,
                                   PolkitSubject  *subject2);

G_END_DECLS

#endif /* __POLKIT_SUBJECT_H__ */
