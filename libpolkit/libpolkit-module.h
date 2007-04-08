/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-module.h : PolicyKit loadable module interface
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBPOLKIT_MODULE_H
#define LIBPOLKIT_MODULE_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit.h>

struct PolKitModuleInterface;
typedef struct PolKitModuleInterface PolKitModuleInterface;

/**
 * PolKitModuleInitialize:
 * @module_interface: the module interface
 * @argc: number of arguments to pass to module
 * @argv: arguments passed to module; the first argument is the filename/path to the module
 *
 * Type of PolicyKit module function to initialize the module.
 *
 * Returns: Whether the module was initialized.
 **/
typedef gboolean (*PolKitModuleInitialize) (PolKitModuleInterface *module_interface, 
                                            int                    argc, 
                                            char                  *argv[]);

/**
 * PolKitModuleShutdown:
 * @module_interface: the module interface
 *
 * Type of PolicyKit module function to shutdown the module.
 **/
typedef void (*PolKitModuleShutdown) (PolKitModuleInterface *module_interface);

/**
 * PolKitModuleGetSeatResourceAssociation:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @visitor: visitor function
 * @user_data: user data
 *
 * Type of PolicyKit module function to implement libpolkit_get_seat_resource_association().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleGetSeatResourceAssociation) (PolKitModuleInterface *module_interface,
                                                                PolKitContext         *pk_context,
                                                                PolKitSeatVisitorCB    visitor,
                                                                gpointer              *user_data);

/**
 * PolKitModuleIsResourceAssociatedWithSeat:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @resource: the resource in question
 * @seat: the seat
 *
 * Type of PolicyKit module function to implement libpolkit_is_resource_associated_with_seat().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleIsResourceAssociatedWithSeat) (PolKitModuleInterface *module_interface,
                                                                  PolKitContext         *pk_context,
                                                                  PolKitResource        *resource,
                                                                  PolKitSeat            *seat);

/**
 * PolKitModuleCanSessionAccessResource:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @session: the session in question
 *
 * Type of PolicyKit module function to implement libpolkit_can_session_access_resource().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleCanSessionAccessResource) (PolKitModuleInterface *module_interface,
                                                              PolKitContext         *pk_context,
                                                              PolKitPrivilege       *privilege,
                                                              PolKitResource        *resource,
                                                              PolKitSession         *session);

/**
 * PolKitModuleCanCallerAccessResource:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @caller: the resource in question
 *
 * Type of PolicyKit module function to implement libpolkit_can_caller_access_resource().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleCanCallerAccessResource) (PolKitModuleInterface *module_interface,
                                                             PolKitContext         *pk_context,
                                                             PolKitPrivilege       *privilege,
                                                             PolKitResource        *resource,
                                                             PolKitCaller          *caller);

PolKitModuleInterface *libpolkit_module_interface_new   (void);
PolKitModuleInterface *libpolkit_module_interface_ref   (PolKitModuleInterface *module_interface);
void                   libpolkit_module_interface_unref (PolKitModuleInterface *module_interface);
const char            *libpolkit_module_get_name        (PolKitModuleInterface *module_interface);

void                   libpolkit_module_set_user_data   (PolKitModuleInterface *module_interface, gpointer user_data);
gpointer               libpolkit_module_get_user_data   (PolKitModuleInterface *module_interface);

void libpolkit_module_set_func_initialize                       (PolKitModuleInterface               *module_interface, 
                                                                 PolKitModuleInitialize               func);
void libpolkit_module_set_func_shutdown                         (PolKitModuleInterface               *module_interface, 
                                                                 PolKitModuleShutdown                 func);
void libpolkit_module_set_func_get_seat_resource_association    (PolKitModuleInterface               *module_interface,
                                                                 PolKitModuleGetSeatResourceAssociation func);
void libpolkit_module_set_func_is_resource_associated_with_seat (PolKitModuleInterface               *module_interface,
                                                                 PolKitModuleIsResourceAssociatedWithSeat func);
void libpolkit_module_set_func_can_session_access_resource      (PolKitModuleInterface               *module_interface,
                                                                 PolKitModuleCanSessionAccessResource func);
void libpolkit_module_set_func_can_caller_access_resource       (PolKitModuleInterface               *module_interface,
                                                                 PolKitModuleCanCallerAccessResource  func);

PolKitModuleInitialize libpolkit_module_get_func_initialize (PolKitModuleInterface *module_interface);
PolKitModuleShutdown libpolkit_module_get_func_shutdown (PolKitModuleInterface *module_interface);
PolKitModuleGetSeatResourceAssociation libpolkit_module_get_func_get_seat_resource_association (PolKitModuleInterface *module_interface);
PolKitModuleIsResourceAssociatedWithSeat libpolkit_module_get_func_is_resource_associated_with_seat (PolKitModuleInterface *module_interface);
PolKitModuleCanSessionAccessResource libpolkit_module_get_func_can_session_access_resource (PolKitModuleInterface *module_interface);
PolKitModuleCanCallerAccessResource libpolkit_module_get_func_can_caller_access_resource (PolKitModuleInterface *module_interface);

/**
 * PolKitModuleControl:
 * @LIBPOLKIT_MODULE_CONTROL_ADVISE: Allow modules, marked with #LIBPOLKIT_MODULE_CONTROL_MANDATORY, down the
 * stack to override results from this module. Modules down the stack that are also marked with 
 * the #LIBPOLKIT_MODULE_CONTROL_ADVISE control will only take effect it they change the result to be "less strict".
 * @LIBPOLKIT_MODULE_CONTROL_MANDATORY: Always use results (unless it returns 
 * #LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE for a given request) from this module, even if it changes whether the
 * result to be "more strict". . If a later module also uses this control, results from that module will override it.
 * @LIBPOLKIT_MODULE_CONTROL_N_CONTROLS: Number of control stanzas
 *
 * The control stanza for a PolicyKit module. This is read from the
 * PolicyKit configuration file (/etc/PolicyKit/PolicyKit.conf) that
 * defines the stacked order of the modules and is chosen by the
 * system administrator. See the definition of #PolKitResult for
 * the definition of "strict" with respect to result values.
 **/
typedef enum
{
        LIBPOLKIT_MODULE_CONTROL_ADVISE,
        LIBPOLKIT_MODULE_CONTROL_MANDATORY,
        LIBPOLKIT_MODULE_CONTROL_N_CONTROLS
} PolKitModuleControl;

const char *
libpolkit_module_control_to_string_representation (PolKitModuleControl module_control);

gboolean
libpolkit_module_control_from_string_representation (const char *string, PolKitModuleControl *out_module_control);

PolKitModuleInterface *libpolkit_module_interface_load_module (const char *name, 
                                                               PolKitModuleControl module_control, 
                                                               int argc, char *argv[]);

PolKitModuleControl libpolkit_module_interface_get_control (PolKitModuleInterface *module_interface);

#endif /* LIBPOLKIT_MODULE_H */
