/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module-allow-all.c : PolicyKit module that says YES to everything
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

#include <libpolkit/libpolkit-module.h>

/* The symbol that libpolkit looks up when loading this module */
bool libpolkit_module_set_functions (PolKitModuleInterface *module_interface);

static bool
_module_init (PolKitModuleInterface *module_interface, int argc, char *argv[])
{
        return true;
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
        return LIBPOLKIT_RESULT_YES;
}

static PolKitResult
_module_can_caller_access_resource (PolKitModuleInterface *module_interface,
                                    PolKitContext         *pk_context,
                                    PolKitAction          *action,
                                    PolKitResource        *resource,
                                    PolKitCaller          *caller)
{
        return LIBPOLKIT_RESULT_YES;
}

bool
libpolkit_module_set_functions (PolKitModuleInterface *module_interface)
{
        bool ret;

        ret = false;
        if (module_interface == NULL)
                goto out;

        libpolkit_module_set_func_initialize (module_interface, _module_init);
        libpolkit_module_set_func_shutdown (module_interface, _module_shutdown);
        libpolkit_module_set_func_can_session_access_resource (module_interface, _module_can_session_access_resource);
        libpolkit_module_set_func_can_caller_access_resource (module_interface, _module_can_caller_access_resource);

        ret = true;
out:
        return ret;
}
