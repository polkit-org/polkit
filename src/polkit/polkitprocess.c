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
#include <string.h>

#include "polkitprocess.h"

/**
 * SECTION:polkitprocess
 * @short_description: Process
 * @include: polkit/polkit.h
 *
 * Represents a process.
 */

/*--------------------------------------------------------------------------------------------------------------*/

struct _PolkitProcessPrivate
{
        GPid pid;
};

enum {
        PROP_0,
        PROP_PID,
};

static void polkit_process_subject_iface_init (PolkitSubjectIface *iface);

G_DEFINE_TYPE_WITH_CODE (PolkitProcess, polkit_process, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT,
                                                polkit_process_subject_iface_init))

#define POLKIT_PROCESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_PROCESS, PolkitProcessPrivate))

static void
polkit_process_get_property (GObject    *object,
                             guint       prop_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
        PolkitProcess *process = POLKIT_PROCESS (object);

        switch (prop_id) {
        case PROP_PID:
                g_value_set_int (value, process->priv->pid);
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_process_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
        PolkitProcess *process = POLKIT_PROCESS (object);

        switch (prop_id) {
        case PROP_PID:
                polkit_process_set_pid (process, g_value_get_int (value));
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_process_init (PolkitProcess *process)
{
        process->priv = POLKIT_PROCESS_GET_PRIVATE (process);
}

static void
polkit_process_finalize (GObject *object)
{
        PolkitProcess *process;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_PROCESS (object));

        process = POLKIT_PROCESS (object);

        G_OBJECT_CLASS (polkit_process_parent_class)->finalize (object);
}

static void
polkit_process_class_init (PolkitProcessClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->get_property = polkit_process_get_property;
        object_class->set_property = polkit_process_set_property;
        object_class->finalize = polkit_process_finalize;

        /**
         * PolkitProcess:pid:
         *
         * The process id.
         */
        g_object_class_install_property (object_class,
                                         PROP_PID,
                                         g_param_spec_int ("pid",
                                                           "pid",
                                                           "The process id",
                                                           -1,
                                                           G_MAXINT, /* TODO: maybe there's a MAX_PID? */
                                                           -1,
                                                           G_PARAM_CONSTRUCT |
                                                           G_PARAM_READWRITE |
                                                           G_PARAM_STATIC_NAME |
                                                           G_PARAM_STATIC_NICK |
                                                           G_PARAM_STATIC_BLURB));

        g_type_class_add_private (klass, sizeof (PolkitProcessPrivate));
}

pid_t
polkit_process_get_pid (PolkitProcess *process)
{
        g_return_val_if_fail (POLKIT_IS_PROCESS (process), -1);
        return process->priv->pid;
}

void
polkit_process_set_pid (PolkitProcess *process,
                          pid_t           pid)
{
        g_return_if_fail (POLKIT_IS_PROCESS (process));
        if (pid != process->priv->pid) {
                process->priv->pid = pid;
                g_object_notify (G_OBJECT (process), "pid");
        }
}

PolkitSubject *
polkit_process_new (pid_t pid)
{
        return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_PROCESS,
                                             "pid", pid,
                                             NULL));
}

static gboolean
polkit_process_equal (PolkitSubject *subject1,
                        PolkitSubject *subject2)
{
        PolkitProcess *process1 = POLKIT_PROCESS (subject1);
        PolkitProcess *process2 = POLKIT_PROCESS (subject2);

        return process1->priv->pid == process2->priv->pid;
}

static void
polkit_process_subject_iface_init (PolkitSubjectIface *iface)
{
        iface->equal = polkit_process_equal;
}
