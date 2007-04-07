/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-context.c : context for PolicyKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "libpolkit-debug.h"
#include "libpolkit-context.h"
#include "libpolkit-privilege-cache.h"

/**
 * SECTION:libpolkit-context
 * @short_description: Context.
 *
 * This class is used to represent the interface to PolicyKit.
 **/

/**
 * PolKitContext:
 *
 * Context object for users of PolicyKit.
 **/
struct PolKitContext
{
        int refcount;

        PolKitContextConfigChangedCB config_changed_cb;
        gpointer config_changed_user_data;

        PolKitContextFileMonitorAddWatch      file_monitor_add_watch_func;
        PolKitContextFileMonitorRemoveWatch   file_monitor_remove_watch_func;

        char *priv_dir;

        PolKitPrivilegeCache *priv_cache;
};

/**
 * libpolkit_context_new:
 * 
 * Create a new context
 * 
 * Returns: the #PolKitPrivilegeCache object
 **/
PolKitContext *
libpolkit_context_new (void)
{
        PolKitContext *pk_context;
        pk_context = g_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        return pk_context;
}

static void
_privilege_dir_events (PolKitContext                 *pk_context,
                       PolKitContextFileMonitorEvent  event_mask,
                       const char                    *path,
                       gpointer                       user_data)
{
        /* mark cache of privilege files as stale.. (will be populated on-demand, see _get_cache()) */
        if (pk_context->priv_cache != NULL) {
                _pk_debug ("Something happened in %s - invalidating cache", pk_context->priv_dir);
                libpolkit_privilege_cache_unref (pk_context->priv_cache);
                pk_context->priv_cache = NULL;
        }

        /* signal that our configuration (may have) changed */
        if (pk_context->config_changed_cb) {
                pk_context->config_changed_cb (pk_context, pk_context->config_changed_user_data);
        }
}

/**
 * libpolkit_context_init:
 * @pk_context: the context object
 * @error: return location for error
 * 
 * Initializes a new context; loads PolicyKit files from
 * /etc/PolicyKit/privileges unless the environment variable
 * $POLKIT_PRIVILEGE_DIR points to a location.
 *
 * Returns: #FALSE if @error was set, otherwise #TRUE
 **/
gboolean
libpolkit_context_init (PolKitContext *pk_context, GError **error)
{
        gboolean ret;
        const char *dirname;

        ret = FALSE;

        dirname = getenv ("POLKIT_PRIVILEGE_DIR");
        if (dirname != NULL) {
                pk_context->priv_dir = g_strdup (dirname);
        } else {
                pk_context->priv_dir = g_strdup (PACKAGE_SYSCONF_DIR "/PolicyKit/privileges");
        }
        _pk_debug ("Using privilege files from directory %s", pk_context->priv_dir);

        /* don't populate the cache until it's needed.. */

        if (pk_context->file_monitor_add_watch_func == NULL) {
                _pk_debug ("No file monitor; cannot monitor '%s' for .priv file changes", dirname);
        } else {
                pk_context->file_monitor_add_watch_func (pk_context, 
                                                         pk_context->priv_dir,
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CREATE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_DELETE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CHANGE,
                                                         _privilege_dir_events,
                                                         NULL);
        }

        /* right now we can't fail - but in the future modules we load may */

        ret = TRUE;
        return ret;
}

/**
 * libpolkit_context_ref:
 * @pk_context: the context object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitContext *
libpolkit_context_ref (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, pk_context);
        pk_context->refcount++;
        return pk_context;
}

/**
 * libpolkit_context_unref:
 * @pk_context: the context object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_context_unref (PolKitContext *pk_context)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;
        g_free (pk_context);
}

/**
 * libpolkit_context_set_config_changed:
 * @pk_context: the context object
 * @cb: the callback to invoke
 * @user_data: user data to pass to the callback
 * 
 * Register the callback function for when configuration changes.
 * Mechanisms should use this callback to e.g. reconfigure all
 * permissions / acl's they have set in response to policy decisions
 * made from information provided by PolicyKit. 
 *
 * Note that this function may be called many times within a short
 * interval due to how file monitoring works if e.g. the user is
 * editing a configuration file (editors typically create back-up
 * files). Mechanisms should use a "cool-off" timer (of, say, one
 * second) to avoid doing many expensive operations (such as
 * reconfiguring all ACL's for all devices) within a very short
 * timeframe.
 **/
void
libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                      PolKitContextConfigChangedCB cb, 
                                      gpointer                     user_data)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

/**
 * libpolkit_context_set_file_monitor:
 * @pk_context: the context object
 * @add_watch_func: the function that the PolicyKit library can invoke to start watching a file
 * @remove_watch_func: the function that the PolicyKit library can invoke to stop watching a file
 * 
 * Register a functions that PolicyKit can use for watching files.
 **/
void
libpolkit_context_set_file_monitor (PolKitContext                        *pk_context, 
                                    PolKitContextFileMonitorAddWatch      add_watch_func,
                                    PolKitContextFileMonitorRemoveWatch   remove_watch_func)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->file_monitor_add_watch_func = add_watch_func;
        pk_context->file_monitor_remove_watch_func = remove_watch_func;
}


/**
 * libpolkit_context_get_privilege_cache:
 * @pk_context: the context
 * 
 * Get the #PolKitPrivilegeCache object that holds all the defined privileges as well as their defaults.
 * 
 * Returns: the #PolKitPrivilegeCache object. Caller shall not unref it.
 **/
PolKitPrivilegeCache *
libpolkit_context_get_privilege_cache (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, NULL);

        if (pk_context->priv_cache == NULL) {
                GError *error;

                _pk_debug ("Populating cache from directory %s", pk_context->priv_dir);

                error = NULL;
                pk_context->priv_cache = libpolkit_privilege_cache_new (pk_context->priv_dir, &error);
                if (pk_context->priv_cache == NULL) {
                        g_warning ("Error loading privilege files from %s: %s", 
                                   pk_context->priv_dir, error->message);
                        g_error_free (error);
                } else {
                        /*libpolkit_privilege_cache_debug (pk_context->priv_cache)*/;
                }
        }

        return pk_context->priv_cache;
}
