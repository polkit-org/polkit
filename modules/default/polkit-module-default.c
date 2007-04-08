/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module-default.c : PolicyKit module for default policy
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

#include <libpolkit/libpolkit-module.h>

/* The symbol that libpolkit looks up when loading this module */
gboolean libpolkit_module_set_functions (PolKitModuleInterface *module_interface);

static gboolean
_module_init (PolKitModuleInterface *module_interface, 
              int argc, 
              char *argv[])
{
        return TRUE;
}

static void
_module_shutdown (PolKitModuleInterface *module_interface)
{
}

static PolKitResult
_module_can_session_access_resource (PolKitModuleInterface *module_interface,
                                     PolKitContext         *pk_context,
                                     PolKitAction          *action,
                                     PolKitResource        *resource,
                                     PolKitSession         *session)
{
        PolKitResult result;
        PolKitPolicyCache *cache;
        PolKitPolicyFileEntry *pfe;

        result = LIBPOLKIT_RESULT_NO;
        cache = libpolkit_context_get_policy_cache (pk_context);
        pfe = libpolkit_policy_cache_get_entry (cache, action);
        return libpolkit_policy_default_can_session_access_resource (
                libpolkit_policy_file_entry_get_default (pfe), 
                action, 
                resource, 
                session);
}

static PolKitResult
_module_can_caller_access_resource (PolKitModuleInterface *module_interface,
                                    PolKitContext         *pk_context,
                                    PolKitAction          *action,
                                    PolKitResource        *resource,
                                    PolKitCaller          *caller)
{
        PolKitResult result;
        PolKitPolicyCache *cache;
        PolKitPolicyFileEntry *pfe;

        result = LIBPOLKIT_RESULT_NO;
        cache = libpolkit_context_get_policy_cache (pk_context);
        pfe = libpolkit_policy_cache_get_entry (cache, action);
        return libpolkit_policy_default_can_caller_access_resource (
                libpolkit_policy_file_entry_get_default (pfe), 
                action, 
                resource, 
                caller);
}

gboolean
libpolkit_module_set_functions (PolKitModuleInterface *module_interface)
{
        gboolean ret;

        ret = FALSE;
        if (module_interface == NULL)
                goto out;

        libpolkit_module_set_func_initialize (module_interface, _module_init);
        libpolkit_module_set_func_shutdown (module_interface, _module_shutdown);
        libpolkit_module_set_func_can_session_access_resource (module_interface, _module_can_session_access_resource);
        libpolkit_module_set_func_can_caller_access_resource (module_interface, _module_can_caller_access_resource);

        ret = TRUE;
out:
        return ret;
}
