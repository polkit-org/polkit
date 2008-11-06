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

#include "config.h"

#include "polkitsubject.h"

/**
 * SECTION:polkitsubject
 * @title: PolkitSubject
 * @short_description: Interface for subjects
 * @include: polkit/polkit.h
 *
 * #PolkitSubject is a very minimal interface for subjects. It provides functions
 * for checking the equality of two subjects
 *
 * To check if two #PolkitSubjects are equal, see polkit_subject_equal().
 **/

static void polkit_subject_base_init  (gpointer g_class);
static void polkit_subject_class_init (gpointer g_class,
                                         gpointer class_data);

GType
polkit_subject_get_type (void)
{
        static volatile gsize g_define_type_id__volatile = 0;

        if (g_once_init_enter (&g_define_type_id__volatile)) {
                const GTypeInfo subject_info = {
                        sizeof (PolkitSubjectIface), /* class_size */
                        polkit_subject_base_init,   /* base_init */
                        NULL,		              /* base_finalize */
                        polkit_subject_class_init,  /* class_init */
                        NULL,		              /* class_finalize */
                        NULL,		              /* class_data */
                        0,
                        0,                            /* n_preallocs */
                        NULL
                };

                GType g_define_type_id =
                        g_type_register_static (G_TYPE_INTERFACE,
                                                "PolkitSubject",
                                                &subject_info,
                                                0);

                g_type_interface_add_prerequisite (g_define_type_id, G_TYPE_OBJECT);

                g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
        }

        return g_define_type_id__volatile;
}

static void
polkit_subject_class_init (gpointer g_class,
                             gpointer class_data)
{
}

static void
polkit_subject_base_init (gpointer g_class)
{
}


/**
 * polkit_subject_equal:
 * @subject1: pointer to the first #PolkitSubject.
 * @subject2: pointer to the second #PolkitSubject.
 *
 * Checks if two subjects are equal.
 *
 * Returns: %TRUE if @subject1 is equal to @subject2. %FALSE otherwise.
 **/
gboolean
polkit_subject_equal (PolkitSubject *subject1,
                      PolkitSubject *subject2)
{
        PolkitSubjectIface *iface;

        if (subject1 == NULL && subject2 == NULL)
                return TRUE;

        if (subject1 == NULL || subject2 == NULL)
                return FALSE;

        if (G_TYPE_FROM_INSTANCE (subject1) != G_TYPE_FROM_INSTANCE (subject2))
                return FALSE;

        iface = POLKIT_SUBJECT_GET_IFACE (subject1);

        return (* iface->equal) (subject1, subject2);
}
