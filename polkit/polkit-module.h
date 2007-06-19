/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module.h : PolicyKit loadable module interface
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_MODULE_H
#define POLKIT_MODULE_H

#include <polkit/polkit-types.h>
#include <polkit/polkit.h>

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
typedef polkit_bool_t     (*PolKitModuleInitialize) (PolKitModuleInterface *module_interface, 
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
 * PolKitModuleCanSessionAccessDoAction:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @session: the session in question
 *
 * Type of PolicyKit module function to implement polkit_can_session_access_do_action().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleCanSessionDoAction) (PolKitModuleInterface *module_interface,
                                                        PolKitContext         *pk_context,
                                                        PolKitAction          *action,
                                                        PolKitSession         *session);

/**
 * PolKitModuleCanCallerAccessDoAction:
 * @module_interface: the module interface
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @caller: the caller in question
 *
 * Type of PolicyKit module function to implement polkit_can_caller_do_action().
 *
 * Returns: the #PolKitResult
 **/
typedef PolKitResult (*PolKitModuleCanCallerDoAction) (PolKitModuleInterface *module_interface,
                                                       PolKitContext         *pk_context,
                                                       PolKitAction          *action,
                                                       PolKitCaller          *caller);

PolKitModuleInterface *polkit_module_interface_new   (void);
PolKitModuleInterface *polkit_module_interface_ref   (PolKitModuleInterface *module_interface);
void                   polkit_module_interface_unref (PolKitModuleInterface *module_interface);
const char            *polkit_module_get_name        (PolKitModuleInterface *module_interface);

void                   polkit_module_set_user_data   (PolKitModuleInterface *module_interface, void *user_data);
void                  *polkit_module_get_user_data   (PolKitModuleInterface *module_interface);

void polkit_module_set_func_initialize                 (PolKitModuleInterface               *module_interface, 
                                                        PolKitModuleInitialize               func);
void polkit_module_set_func_shutdown                   (PolKitModuleInterface               *module_interface, 
                                                        PolKitModuleShutdown                 func);
void polkit_module_set_func_can_session_do_action      (PolKitModuleInterface               *module_interface,
                                                        PolKitModuleCanSessionDoAction       func);
void polkit_module_set_func_can_caller_do_action       (PolKitModuleInterface               *module_interface,
                                                        PolKitModuleCanCallerDoAction        func);

PolKitModuleInitialize polkit_module_get_func_initialize (PolKitModuleInterface *module_interface);
PolKitModuleShutdown polkit_module_get_func_shutdown (PolKitModuleInterface *module_interface);
PolKitModuleCanSessionDoAction polkit_module_get_func_can_session_do_action (PolKitModuleInterface *module_interface);
PolKitModuleCanCallerDoAction polkit_module_get_func_can_caller_do_action (PolKitModuleInterface *module_interface);

/**
 * PolKitModuleControl:
 * @POLKIT_MODULE_CONTROL_ADVISE: Allow modules, marked with #POLKIT_MODULE_CONTROL_MANDATORY, down the
 * stack to override results from this module. Modules down the stack that are also marked with 
 * the #POLKIT_MODULE_CONTROL_ADVISE control will only take effect it they change the result to be "less strict".
 * @POLKIT_MODULE_CONTROL_MANDATORY: Always use results (unless it returns 
 * #POLKIT_RESULT_UNKNOWN_ACTION for a given request) from this module, even if it changes whether the
 * result to be "more strict". . If a later module also uses this control, results from that module will override it.
 * @POLKIT_MODULE_CONTROL_N_CONTROLS: Number of control stanzas
 *
 * The control stanza for a PolicyKit module. This is read from the
 * PolicyKit configuration file (/etc/PolicyKit/PolicyKit.conf) that
 * defines the stacked order of the modules and is chosen by the
 * system administrator. See the definition of #PolKitResult for
 * the definition of "strict" with respect to result values.
 **/
typedef enum
{
        POLKIT_MODULE_CONTROL_ADVISE,
        POLKIT_MODULE_CONTROL_MANDATORY,
        POLKIT_MODULE_CONTROL_N_CONTROLS
} PolKitModuleControl;

const char *
polkit_module_control_to_string_representation (PolKitModuleControl module_control);

polkit_bool_t
polkit_module_control_from_string_representation (const char *string, PolKitModuleControl *out_module_control);

PolKitModuleInterface *polkit_module_interface_load_module (const char *name, 
                                                               PolKitModuleControl module_control, 
                                                               int argc, char *argv[]);

PolKitModuleControl polkit_module_interface_get_control (PolKitModuleInterface *module_interface);


polkit_bool_t
polkit_module_interface_check_builtin_confinement_for_session (PolKitModuleInterface *module_interface,
                                                                  PolKitContext   *pk_context,
                                                                  PolKitAction    *action,
                                                                  PolKitSession   *session);

polkit_bool_t
polkit_module_interface_check_builtin_confinement_for_caller (PolKitModuleInterface *module_interface,
                                                                 PolKitContext   *pk_context,
                                                                 PolKitAction    *action,
                                                                 PolKitCaller    *caller);

#endif /* POLKIT_MODULE_H */
