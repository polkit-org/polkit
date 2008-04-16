/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-context.c : context for PolicyKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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
#ifdef HAVE_SOLARIS
#include <port.h>
#include <sys/stat.h>
#else
#include <sys/inotify.h>
#endif
#include <syslog.h>

#include "polkit-config.h"
#include "polkit-debug.h"
#include "polkit-context.h"
#include "polkit-policy-cache.h"
#include "polkit-private.h"
#include "polkit-test.h"

/**
 * SECTION:polkit
 * @short_description: Centralized policy management.
 *
 * libpolkit is a C library for centralized policy management.
 **/

/**
 * SECTION:polkit-context
 * @title: Context
 * @short_description: The main interface used to query PolicyKit.
 *
 * This class is used to represent the interface to PolicyKit - it is
 * used by Mechanisms that use PolicyKit for making
 * decisions. Typically, it's used as a singleton:
 *
 * <itemizedlist>
 * <listitem>First, the Mechanism need to declare one or more PolicyKit Actions by dropping a <literal>.policy</literal> file into <literal>/usr/share/PolicyKit/policy</literal>. This is described in the PolicyKit specification.</listitem>
 * <listitem>The mechanism starts up and uses polkit_context_new() to create a new context</listitem>
 * <listitem>If the mechanism is a long running daemon, it should use polkit_context_set_config_changed() to register a callback when configuration changes. This is useful if, for example, the mechanism needs to revise decisions based on earlier answers from libpolkit. For example, a daemon that manages permissions on <literal>/dev</literal> may want to add/remove ACL's when configuration changes; for example, the system administrator could have changed the PolicyKit configuration file <literal>/etc/PolicyKit/PolicyKit.conf</literal> such that some user is now privileged to access a specific device.</listitem>
 * <listitem>If polkit_context_set_config_changed() is used, the mechanism must also use polkit_context_set_io_watch_functions() to integrate libpolkit into the mainloop.</listitem>
 * <listitem>The mechanism needs to call polkit_context_init() such that libpolkit can load configuration files and properly initialize.</listitem>
 * <listitem>Whenever the mechanism needs to make a decision whether a caller is allowed to make a perform some action, the mechanism prepares a #PolKitAction and #PolKitCaller object (or #PolKitSession if applicable) and calls polkit_context_can_caller_do_action() (or polkit_context_can_session_do_action() if applicable). The mechanism may use the libpolkit-dbus library (specifically the polkit_caller_new_from_dbus_name() or polkit_caller_new_from_pid() functions) but may opt, for performance reasons, to construct #PolKitCaller (or #PolKitSession if applicable) from it's own cache of information.</listitem>
 * <listitem>The mechanism will get a #PolKitResult object back that describes whether it should carry out the action. This result stems from a number of sources, see the PolicyKit specification document for details.</listitem>
 * <listitem>If the result is #POLKIT_RESULT_YES, the mechanism should carry out the action. If the result is not #POLKIT_RESULT_YES nor #POLKIT_RESULT_UNKNOWN (this would never be returned but is mentioned here for completeness), the mechanism should throw an expcetion to the caller detailing the #PolKitResult as a textual string using polkit_result_to_string_representation(). For example, if the mechanism is using D-Bus it could throw an com.some-mechanism.DeniedByPolicy exception with the #PolKitResult textual representation in the detail field. Then the caller can interpret this exception and then act on it (for example it can attempt to gain that privilege).</listitem>
 * </itemizedlist>
 *
 * For more information about using PolicyKit in mechanisms and
 * callers, refer to the PolicyKit-gnome project which includes a
 * sample application on how to use this in the GNOME desktop.
 **/

/**
 * PolKitContext:
 *
 * Context object for users of PolicyKit.
 **/
struct _PolKitContext
{
        int refcount;

        PolKitContextConfigChangedCB config_changed_cb;
        void *config_changed_user_data;

        PolKitContextAddIOWatch      io_add_watch_func;
        PolKitContextRemoveIOWatch   io_remove_watch_func;

        char *policy_dir;

        PolKitPolicyCache *priv_cache;

        PolKitConfig *config;

        PolKitAuthorizationDB *authdb;

        polkit_bool_t load_descriptions;

        int inotify_fd;
        int inotify_fd_watch_id;
        int inotify_config_wd;
        int inotify_policy_wd;
        int inotify_grant_perm_wd;
};

/**
 * polkit_context_new:
 * 
 * Create a new context
 * 
 * Returns: the object
 **/
PolKitContext *
polkit_context_new (void)
{
        PolKitContext *pk_context;
        pk_context = kit_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        /* TODO: May want to rethink instantiating this on demand.. */
        pk_context->authdb = _polkit_authorization_db_new ();
        return pk_context;
}

/**
 * polkit_context_init:
 * @pk_context: the context object
 * @error: return location for error
 * 
 * Initializes a new context; loads PolicyKit files from
 * /usr/share/PolicyKit/policy.
 *
 * Returns: #FALSE if @error was set, otherwise #TRUE
 **/
polkit_bool_t
polkit_context_init (PolKitContext *pk_context, PolKitError **error)
{
        kit_return_val_if_fail (pk_context != NULL, FALSE);

        pk_context->policy_dir = kit_strdup (PACKAGE_DATA_DIR "/PolicyKit/policy");
        polkit_debug ("Using policy files from directory %s", pk_context->policy_dir);

        /* NOTE: we don't populate the cache until it's needed.. */

        /* NOTE: we don't load the configuration file until it's needed */

#ifdef HAVE_SOLARIS
        if (pk_context->io_add_watch_func != NULL) {
                pk_context->inotify_fd = port_create ();
                if (pk_context->inotify_fd < 0) {
                        polkit_debug ("failed to port_create: %s", strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                /* Watch the /etc/PolicyKit/PolicyKit.conf file */
                pk_context->inotify_config_wd = port_add_watch (pk_context->inotify_fd,
                                                                   PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf",
                                                                   FILE_MODIFIED | FILE_ATTRIB);
                if (pk_context->inotify_config_wd < 0) {
                        polkit_debug ("failed to add watch on file '" PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                /* Watch the /usr/share/PolicyKit/policy directory */
                pk_context->inotify_policy_wd = port_add_watch (pk_context->inotify_fd,
                                                                   PACKAGE_DATA_DIR "/PolicyKit/policy",
                                                                   FILE_MODIFIED | FILE_ATTRIB);
                if (pk_context->inotify_policy_wd < 0) {
                        polkit_debug ("failed to add watch on directory '" PACKAGE_DATA_DIR "/PolicyKit/policy': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

#ifdef POLKIT_AUTHDB_DEFAULT
                /* Watch the /var/lib/misc/PolicyKit.reload file */
                pk_context->inotify_grant_perm_wd = port_add_watch (pk_context->inotify_fd,
                                                                       PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload",
                                                                       FILE_MODIFIED | FILE_ATTRIB);
                if (pk_context->inotify_grant_perm_wd < 0) {
                        polkit_debug ("failed to add watch on file '" PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }
#endif

                pk_context->inotify_fd_watch_id = pk_context->io_add_watch_func (pk_context, pk_context->inotify_fd);
                if (pk_context->inotify_fd_watch_id == 0) {
                        polkit_debug ("failed to add io watch");
                        /* TODO: set error */
                        goto error;
                }
        }

#else
        if (pk_context->io_add_watch_func != NULL) {
                pk_context->inotify_fd = inotify_init ();
                if (pk_context->inotify_fd < 0) {
                        polkit_debug ("failed to initialize inotify: %s", strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                /* Watch the /etc/PolicyKit/PolicyKit.conf file */
                pk_context->inotify_config_wd = inotify_add_watch (pk_context->inotify_fd, 
                                                                   PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf", 
                                                                   IN_MODIFY | IN_CREATE | IN_ATTRIB);
                if (pk_context->inotify_config_wd < 0) {
                        polkit_debug ("failed to add watch on file '" PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                /* Watch the /usr/share/PolicyKit/policy directory */
                pk_context->inotify_policy_wd = inotify_add_watch (pk_context->inotify_fd, 
                                                                   PACKAGE_DATA_DIR "/PolicyKit/policy", 
                                                                   IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB);
                if (pk_context->inotify_policy_wd < 0) {
                        polkit_debug ("failed to add watch on directory '" PACKAGE_DATA_DIR "/PolicyKit/policy': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

#ifdef POLKIT_AUTHDB_DEFAULT
                /* Watch the /var/lib/misc/PolicyKit.reload file */
                pk_context->inotify_grant_perm_wd = inotify_add_watch (pk_context->inotify_fd, 
                                                                       PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload", 
                                                                       IN_MODIFY | IN_CREATE | IN_ATTRIB);
                if (pk_context->inotify_grant_perm_wd < 0) {
                        polkit_debug ("failed to add watch on file '" PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }
#endif

                pk_context->inotify_fd_watch_id = pk_context->io_add_watch_func (pk_context, pk_context->inotify_fd);
                if (pk_context->inotify_fd_watch_id == 0) {
                        polkit_debug ("failed to add io watch");
                        /* TODO: set error */
                        goto error;
                }
        }
#endif

        return TRUE;
error:
        return FALSE;
}

#ifdef HAVE_SOLARIS

struct fileportinfo {
        struct file_obj fobj;
        int events;
        int port;
};

/**
 * port_add_watch:
 * @port: the port object
 * @name: filename which will be added to the port
 * @events: the event which will be watched for
 *
 * add file watch .
 *
 * Returns: the object
 **/
int
port_add_watch (int port, const char *name, uint32_t events)
{
        struct fileportinfo *fpi;

        if ( (fpi = kit_malloc (sizeof(struct fileportinfo)) ) == NULL ) {
                polkit_debug ("Faile to kit_malloc!");
                /* TODO: set error */
                return -1;
        }

        fpi->fobj.fo_name = strdup (name);
        fpi->events = events;
        fpi->port = port;

        if ( file_associate (fpi, events) < 0 ) {
                polkit_debug ("Failed to associate with file %s: %s", fpi->fobj.fo_name, strerror (errno));
                /* TODO: set error */
                return -1;
        }
        return 0;
}

int
file_associate (struct fileportinfo *fpinfo, int events)
{
        struct stat sb;

        if ( stat (fpinfo->fobj.fo_name, &sb) == -1) {
                polkit_debug ("Failed to stat file %s: %s", fpinfo->fobj.fo_name, strerror (errno));
                /* TODO: set error */
                return -1;
        }

        fpinfo->fobj.fo_atime = sb.st_atim;
        fpinfo->fobj.fo_mtime = sb.st_mtim;
        fpinfo->fobj.fo_ctime = sb.st_ctim;

        if ( port_associate (fpinfo->port, PORT_SOURCE_FILE, (uintptr_t)&(fpinfo->fobj), events, (void *)fpinfo ) == -1) {
                polkit_debug ("Failed to register file %s: %s", fpinfo->fobj.fo_name, strerror (errno));
                /* TODO: set error */
                return -1;
        }
        return 0;
}
#endif

/**
 * polkit_context_ref:
 * @pk_context: the context object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitContext *
polkit_context_ref (PolKitContext *pk_context)
{
        kit_return_val_if_fail (pk_context != NULL, pk_context);
        pk_context->refcount++;
        return pk_context;
}

/**
 * polkit_context_unref:
 * @pk_context: the context object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_context_unref (PolKitContext *pk_context)
{

        kit_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;

        kit_free (pk_context);
}

/**
 * polkit_context_set_config_changed:
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
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_config_changed (PolKitContext                *pk_context, 
                                   PolKitContextConfigChangedCB  cb, 
                                   void                         *user_data)
{
        kit_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

/**
 * polkit_context_io_func:
 * @pk_context: the object
 * @fd: the file descriptor passed to the supplied function of type #PolKitContextAddIOWatch.
 * 
 * Method that the application must call when there is data to read
 * from a file descriptor registered with the supplied function of
 * type #PolKitContextAddIOWatch.
 **/
void 
polkit_context_io_func (PolKitContext *pk_context, int fd)
{
        polkit_bool_t config_changed;

        kit_return_if_fail (pk_context != NULL);

        polkit_debug ("polkit_context_io_func: data on fd %d", fd);

        config_changed = FALSE;

#ifdef HAVE_SOLARIS
        if (fd == pk_context->inotify_fd) {
                port_event_t pe;
                struct file_obj *fobjp;
                struct fileportinfo *fpip;

                while ( !port_get (fd, &pe, NULL) ) {
                        switch (pe.portev_source) {
                        case PORT_SOURCE_FILE:
                                fpip = (struct fileportinfo *)pe.portev_object;
                                fobjp = &fpip->fobj;
                                polkit_debug ("filename = %s, events = %d", fobjp->fo_name, pe.portev_events);
                                config_changed = TRUE;
                                polkit_debug ("Config changed");
                                file_associate ((struct fileportinfo *)pe.portev_object, pe.portev_events);
                                break;
                        default:
                                polkit_debug ("Event from unexpected source");
                        }
                        if ( config_changed )
                                break;
                }
        }

#else
        if (fd == pk_context->inotify_fd) {
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN        (1024 * (EVENT_SIZE + 16))
                char buf[BUF_LEN];
                int len;
                int i = 0;
again:
                len = read (fd, buf, BUF_LEN);
                if (len < 0) {
                        if (errno == EINTR) {
                                goto again;
                        } else {
                                polkit_debug ("read: %s", strerror (errno));
                        }
                } else if (len > 0) {
                        /* BUF_LEN too small? */
                }
                while (i < len) {
                        struct inotify_event *event;
                        event = (struct inotify_event *) &buf[i];
                        polkit_debug ("wd=%d mask=%u cookie=%u len=%u",
                                   event->wd, event->mask, event->cookie, event->len);

                        polkit_debug ("config changed!");
                        config_changed = TRUE;

                        i += EVENT_SIZE + event->len;
                }
        }
#endif

        if (config_changed) {
                polkit_context_force_reload (pk_context);

                if (pk_context->config_changed_cb != NULL) {
                        pk_context->config_changed_cb (pk_context, 
                                                       pk_context->config_changed_user_data);
                }
        }
}

/**
 * polkit_context_force_reload:
 * @pk_context: context
 *
 * Force a reload. 
 *
 * Note that there is no reason to call this method in response to a
 * config changed callback.
 *
 * Since: 0.7 
 */
void
polkit_context_force_reload (PolKitContext *pk_context)
{
        kit_return_if_fail (pk_context != NULL);

        /* purge existing policy files */
        polkit_debug ("purging policy files");
        if (pk_context->priv_cache != NULL) {
                polkit_policy_cache_unref (pk_context->priv_cache);
                pk_context->priv_cache = NULL;
        }
        
        /* Purge existing old config file */
        polkit_debug ("purging configuration file");
        if (pk_context->config != NULL) {
                polkit_config_unref (pk_context->config);
                pk_context->config = NULL;
        }
        
        /* Purge authorization entries from the cache */
        _polkit_authorization_db_invalidate_cache (pk_context->authdb);
}


/**
 * polkit_context_set_io_watch_functions:
 * @pk_context: the context object
 * @io_add_watch_func: the function that the PolicyKit library can invoke to start watching a file descriptor
 * @io_remove_watch_func: the function that the PolicyKit library can invoke to stop watching a file descriptor
 * 
 * Register a functions that PolicyKit can use for watching IO descriptors.
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_io_watch_functions (PolKitContext                        *pk_context, 
                                       PolKitContextAddIOWatch               io_add_watch_func,
                                       PolKitContextRemoveIOWatch            io_remove_watch_func)
{
        kit_return_if_fail (pk_context != NULL);
        pk_context->io_add_watch_func = io_add_watch_func;
        pk_context->io_remove_watch_func = io_remove_watch_func;
}

/**
 * polkit_context_set_load_descriptions:
 * @pk_context: the context
 * 
 * Set whether policy descriptions should be loaded. By default these
 * are not loaded to keep memory use down. TODO: specify whether they
 * are localized and how.
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_load_descriptions  (PolKitContext *pk_context)
{
        kit_return_if_fail (pk_context != NULL);
        pk_context->load_descriptions = TRUE;
}

/**
 * polkit_context_get_policy_cache:
 * @pk_context: the context
 * 
 * Get the #PolKitPolicyCache object that holds all the defined policies as well as their defaults.
 * 
 * Returns: the #PolKitPolicyCache object. Caller shall not unref it.
 **/
PolKitPolicyCache *
polkit_context_get_policy_cache (PolKitContext *pk_context)
{
        kit_return_val_if_fail (pk_context != NULL, NULL);

        if (pk_context->priv_cache == NULL) {
                PolKitError *error;

                polkit_debug ("Populating cache from directory %s", pk_context->policy_dir);

                error = NULL;
                pk_context->priv_cache = _polkit_policy_cache_new (pk_context->policy_dir, 
                                                                   pk_context->load_descriptions, 
                                                                   &error);
                if (pk_context->priv_cache == NULL) {
                        kit_warning ("Error loading policy files from %s: %s", 
                                   pk_context->policy_dir, polkit_error_get_error_message (error));
                        polkit_error_free (error);
                } else {
                        polkit_policy_cache_debug (pk_context->priv_cache);
                }
        }

        return pk_context->priv_cache;
}


/**
 * polkit_context_is_session_authorized:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @session: the session in question
 * @error: return location for error
 *
 * Determine if any caller from a giver session is authorized to do a
 * given action.
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action. 
 *
 * Since: 0.7
 */
PolKitResult
polkit_context_is_session_authorized (PolKitContext         *pk_context,
                                      PolKitAction          *action,
                                      PolKitSession         *session,
                                      PolKitError          **error)
{
        PolKitPolicyCache *cache;
        PolKitResult result_from_config;
        PolKitResult result_from_grantdb;
        polkit_bool_t from_authdb;
        polkit_bool_t from_authdb_negative;
        PolKitResult result;
        PolKitConfig *config;

        result = POLKIT_RESULT_NO;
        kit_return_val_if_fail (pk_context != NULL, result);

        config = polkit_context_get_config (pk_context, NULL);
        /* if the configuration file is malformed, always say no */
        if (config == NULL)
                goto out;

        if (action == NULL || session == NULL)
                goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_session_validate (session))
                goto out;

        cache = polkit_context_get_policy_cache (pk_context);
        if (cache == NULL)
                goto out;

        result_from_config = polkit_config_can_session_do_action (config, action, session);

        result_from_grantdb = POLKIT_RESULT_UNKNOWN;
        from_authdb_negative = FALSE;
        if (polkit_authorization_db_is_session_authorized (pk_context->authdb, 
                                                           action, 
                                                           session,
                                                           &from_authdb,
                                                           &from_authdb_negative,
                                                           NULL /* TODO */)) {
                if (from_authdb)
                        result_from_grantdb = POLKIT_RESULT_YES;
        }

        /* Fist, the config file is authoritative.. so only use the
         * value from the authdb if the config file allows to gain via
         * authentication 
         */
        if (result_from_config != POLKIT_RESULT_UNKNOWN) {
                /* it does.. use it.. although try to use an existing grant if there is one */
                if ((result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS) &&
                    result_from_grantdb == POLKIT_RESULT_YES) {
                        result = POLKIT_RESULT_YES;
                } else {
                        result = result_from_config;
                }
                goto found;
        }

        /* If we have a positive answer from the authdb, use it */
        if (result_from_grantdb == POLKIT_RESULT_YES) {
                result = POLKIT_RESULT_YES;
                goto found;
        }

        /* Otherwise, unless we found a negative auth, fall back to defaults as specified in the .policy file */
        if (!from_authdb_negative) {
                PolKitPolicyFileEntry *pfe;

                pfe = polkit_policy_cache_get_entry (cache, action);
                if (pfe != NULL) {
                        PolKitPolicyDefault *policy_default;

                        policy_default = polkit_policy_file_entry_get_default (pfe);
                        if (policy_default != NULL) {
                                result = polkit_policy_default_can_session_do_action (policy_default, action, session);
                        }
                }
        }

found:
        /* Never return UNKNOWN to user */
        if (result == POLKIT_RESULT_UNKNOWN)
                result = POLKIT_RESULT_NO;

out:
        polkit_debug ("... result was %s", polkit_result_to_string_representation (result));
        return result;
}

/**
 * polkit_context_is_caller_authorized:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @caller: the caller in question
 * @revoke_if_one_shot: Whether to revoke one-shot authorizations. See
 * below for discussion.
 * @error: return location for error
 *
 * Determine if a given caller is authorized to do a given
 * action. 
 *
 * It is important to understand how one-shot authorizations work.
 * The revoke_if_one_shot parameter, if #TRUE, specifies whether
 * one-shot authorizations should be revoked if they are used
 * to make the decision to return #POLKIT_RESULT_YES.
 *
 * UI applications wanting to hint whether a caller is authorized must
 * pass #FALSE here. Mechanisms that wants to check authorizations
 * before carrying out work on behalf of a caller must pass #TRUE
 * here.
 *
 * As a side-effect, any process with the authorization
 * org.freedesktop.policykit.read can revoke one-shot authorizations
 * from other users. Even though the window for doing so is small
 * (one-shot auths are typically used right away), be careful who you
 * grant that authorization to.
 *
 * This can fail with the following errors: 
 * #POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action. 
 *
 * Since: 0.7
 */
PolKitResult
polkit_context_is_caller_authorized (PolKitContext         *pk_context,
                                     PolKitAction          *action,
                                     PolKitCaller          *caller,
                                     polkit_bool_t          revoke_if_one_shot,
                                     PolKitError          **error)
{
        PolKitPolicyCache *cache;
        PolKitResult result;
        PolKitResult result_from_config;
        PolKitResult result_from_grantdb;
        PolKitConfig *config;
        polkit_bool_t from_authdb;
        polkit_bool_t from_authdb_negative;

        result = POLKIT_RESULT_NO;
        kit_return_val_if_fail (pk_context != NULL, result);

        /* if the configuration file is malformed, always say no */
        config = polkit_context_get_config (pk_context, NULL);
        if (config == NULL)
                goto out;

        if (action == NULL || caller == NULL)
                goto out;

        cache = polkit_context_get_policy_cache (pk_context);
        if (cache == NULL)
                goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_caller_validate (caller))
                goto out;

        result_from_config = polkit_config_can_caller_do_action (config, action, caller);

        result_from_grantdb = POLKIT_RESULT_UNKNOWN;
        from_authdb_negative = FALSE;
        if (polkit_authorization_db_is_caller_authorized (pk_context->authdb, 
                                                          action, 
                                                          caller,
                                                          revoke_if_one_shot,
                                                          &from_authdb,
                                                          &from_authdb_negative, 
                                                          NULL /* TODO */)) {
                if (from_authdb)
                        result_from_grantdb = POLKIT_RESULT_YES;
        }

        /* Fist, the config file is authoritative.. so only use the
         * value from the authdb if the config file allows to gain via
         * authentication 
         */
        if (result_from_config != POLKIT_RESULT_UNKNOWN) {
                /* it does.. use it.. although try to use an existing grant if there is one */
                if ((result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION ||
                     result_from_config == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS) &&
                    result_from_grantdb == POLKIT_RESULT_YES) {
                        result = POLKIT_RESULT_YES;
                } else {
                        result = result_from_config;
                }
                goto found;
        }

        /* If we have a positive answer from the authdb, use it */
        if (result_from_grantdb == POLKIT_RESULT_YES) {
                result = POLKIT_RESULT_YES;
                goto found;
        }

        /* Otherwise, unless we found a negative auth, fall back to defaults as specified in the .policy file */
        if (!from_authdb_negative) {
                PolKitPolicyFileEntry *pfe;

                pfe = polkit_policy_cache_get_entry (cache, action);
                if (pfe != NULL) {
                        PolKitPolicyDefault *policy_default;

                        policy_default = polkit_policy_file_entry_get_default (pfe);
                        if (policy_default != NULL) {
                                result = polkit_policy_default_can_caller_do_action (policy_default, action, caller);
                        }
                }
        }

found:

        /* Never return UNKNOWN to user */
        if (result == POLKIT_RESULT_UNKNOWN)
                result = POLKIT_RESULT_NO;
out:
        polkit_debug ("... result was %s", polkit_result_to_string_representation (result));
        return result;
}

/**
 * polkit_context_can_session_do_action:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @session: the session in question
 *
 * Determine if a given session can do a given action.
 *
 * This can fail with the following errors: 
 * #POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS
 *
 * Returns: A #PolKitResult - can only be one of
 * #POLKIT_RESULT_YES, #POLKIT_RESULT_NO.
 *
 * Deprecated: 0.7: use polkit_context_is_session_authorized() instead.
 */
PolKitResult
polkit_context_can_session_do_action (PolKitContext   *pk_context,
                                      PolKitAction    *action,
                                      PolKitSession   *session)
{
        return polkit_context_is_session_authorized (pk_context, action, session, NULL);
}

/**
 * polkit_context_can_caller_do_action:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @caller: the caller in question
 *
 * Determine if a given caller can do a given action.
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action
 *
 * Deprecated: 0.7: use polkit_context_is_caller_authorized() instead.
 */
PolKitResult
polkit_context_can_caller_do_action (PolKitContext   *pk_context,
                                     PolKitAction    *action,
                                     PolKitCaller    *caller)
{
        return polkit_context_is_caller_authorized (pk_context, action, caller, FALSE, NULL);
}

/**
 * polkit_context_get_config:
 * @pk_context: the PolicyKit context
 * @error: Return location for error
 *
 * Returns an object that provides access to the
 * /etc/PolicyKit/PolicyKit.conf configuration files. Applications
 * using PolicyKit should never use this method; it's only here for
 * integration with other PolicyKit components.
 *
 * Returns: A #PolKitConfig object or NULL if the configuration file
 * is malformed. Caller should not unref this object.
 */
PolKitConfig *
polkit_context_get_config (PolKitContext *pk_context, PolKitError **error)
{
        if (pk_context->config == NULL) {
                PolKitError **pk_error;
                PolKitError *pk_error2;

                pk_error2 = NULL;
                if (error != NULL)
                        pk_error = error;
                else
                        pk_error = &pk_error2;

                polkit_debug ("loading configuration file");
                pk_context->config = polkit_config_new (PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf", pk_error);
                /* if configuration file was bad, log it */
                if (pk_context->config == NULL) {
                        kit_warning ("failed to load configuration file: %s", 
                                     polkit_error_get_error_message (*pk_error));
                        if (pk_error == &pk_error2)
                                polkit_error_free (*pk_error);
                }
        }
        return pk_context->config;
}

/**
 * polkit_context_get_authorization_db:
 * @pk_context: the PolicyKit context
 * 
 * Returns an object that provides access to the authorization
 * database. Applications using PolicyKit should never use this
 * method; it's only here for integration with other PolicyKit
 * components.
 *
 * Returns: A #PolKitAuthorizationDB object. Caller should not unref
 * this object.
 */
PolKitAuthorizationDB *
polkit_context_get_authorization_db (PolKitContext *pk_context)
{
        return pk_context->authdb;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_context = {
        "polkit_context",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */
