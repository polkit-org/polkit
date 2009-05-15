/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <polkitbackend/polkitbackend.h>

#include <glib/gi18n-lib.h>

#define POLKIT_EXEC_TYPE_ACTION_LOOKUP          (polkit_exec_action_lookup_get_type())
#define POLKIT_EXEC_ACTION_LOOKUP(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_EXEC_TYPE_ACTION_LOOKUP, PolkitExecActionLookup))
#define POLKIT_EXEC_ACTION_LOOKUP_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_EXEC_TYPE_ACTION_LOOKUP, PolkitExecActionLookupClass))
#define POLKIT_EXEC_ACTION_LOOKUP_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_EXEC_TYPE_ACTION_LOOKUP, PolkitExecActionLookupClass))
#define POLKIT_EXEC_IS_ACTION_LOOKUP(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_EXEC_TYPE_ACTION_LOOKUP))
#define POLKIT_EXEC_IS_ACTION_LOOKUP_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_EXEC_TYPE_ACTION_LOOKUP))

typedef struct _PolkitExecActionLookup PolkitExecActionLookup;
typedef struct _PolkitExecActionLookupClass PolkitExecActionLookupClass;

struct _PolkitExecActionLookup
{
  GObject parent;
};

struct _PolkitExecActionLookupClass
{
  GObjectClass parent_class;
};

GType polkit_exec_action_lookup_get_type (void) G_GNUC_CONST;

static void polkit_backend_action_lookup_iface_init (PolkitBackendActionLookupIface *iface);

#define _G_IMPLEMENT_INTERFACE_DYNAMIC(TYPE_IFACE, iface_init)                                                \
{                                                                                                             \
  const GInterfaceInfo g_implement_interface_info = {                   \
    (GInterfaceInitFunc) iface_init, NULL, NULL                         \
  };                                                                    \
  g_type_module_add_interface (type_module, g_define_type_id, TYPE_IFACE, &g_implement_interface_info); \
}

G_DEFINE_DYNAMIC_TYPE_EXTENDED (PolkitExecActionLookup,
                                polkit_exec_action_lookup,
                                G_TYPE_OBJECT,
                                0,
                                _G_IMPLEMENT_INTERFACE_DYNAMIC (POLKIT_BACKEND_TYPE_ACTION_LOOKUP,
                                                                polkit_backend_action_lookup_iface_init))

static void
polkit_exec_action_lookup_init (PolkitExecActionLookup *lookup)
{
}

static void
polkit_exec_action_lookup_class_finalize (PolkitExecActionLookupClass *klass)
{
}

static void
polkit_exec_action_lookup_class_init (PolkitExecActionLookupClass *klass)
{
}

/* ---------------------------------------------------------------------------------------------------- */

static gchar *
polkit_exec_action_lookup_get_message   (PolkitBackendActionLookup *lookup,
                                         const gchar               *action_id,
                                         GHashTable                *details,
                                         PolkitActionDescription   *action_description)
{
  gchar *ret;
  const gchar *s;
  const gchar *s2;

  ret = NULL;

  if (g_strcmp0 (action_id, "org.freedesktop.policykit.exec") != 0)
    goto out;

  s = g_hash_table_lookup (details, "program");
  if (s == NULL)
    goto out;

  s2 = g_hash_table_lookup (details, "uid");
  if (s2 == NULL)
    goto out;

  if (g_strcmp0 (s2, "0") == 0)
    {
      /* Translator: %s is a fully qualified path to the executable */
      ret = g_strdup_printf (_("Authentication is needed to run `%s' as the super user"), s);
    }
  else
    {
      /* Translator: %s is a fully qualified path to the executable */
      ret = g_strdup_printf (_("Authentication is needed to run `%s' as another user"), s);
    }

 out:
  return ret;
}

static gchar *
polkit_exec_action_lookup_get_icon_name (PolkitBackendActionLookup *lookup,
                                         const gchar               *action_id,
                                         GHashTable                *details,
                                         PolkitActionDescription   *action_description)
{
  gchar *ret;

  ret = NULL;

  /* explicitly left blank for now */

  return ret;
}

static GHashTable *
polkit_exec_action_lookup_get_details   (PolkitBackendActionLookup *lookup,
                                          const gchar               *action_id,
                                          GHashTable                *details,
                                          PolkitActionDescription   *action_desc)
{
  const gchar *s;
  const gchar *s2;
  GHashTable *ret;

  ret = NULL;

  if (action_desc != NULL &&
      polkit_action_description_get_annotation (action_desc, "org.freedesktop.policykit.exec.path") == NULL)
    goto out;

  ret = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

  s = g_hash_table_lookup (details, "command-line");
  if (s != NULL)
    {
      g_hash_table_insert (ret,
                           _("Command"),
                           g_strdup (s));
    }

  s = g_hash_table_lookup (details, "user");
  s2 = g_hash_table_lookup (details, "uid");
  if (s != NULL)
    {
      if (g_strcmp0 (s2, "0") == 0)
        s = _("Super User (root)");
      g_hash_table_insert (ret,
                           _("Run As"),
                           g_strdup (s));
    }

 out:
  return ret;
}

static void
polkit_backend_action_lookup_iface_init (PolkitBackendActionLookupIface *iface)
{
  iface->get_message   = polkit_exec_action_lookup_get_message;
  iface->get_icon_name = polkit_exec_action_lookup_get_icon_name;
  iface->get_details   = polkit_exec_action_lookup_get_details;
}

/* ---------------------------------------------------------------------------------------------------- */

void
g_io_module_load (GIOModule *module)
{
  bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

  polkit_exec_action_lookup_register_type (G_TYPE_MODULE (module));

  g_io_extension_point_implement (POLKIT_BACKEND_ACTION_LOOKUP_EXTENSION_POINT_NAME,
                                  POLKIT_EXEC_TYPE_ACTION_LOOKUP,
                                  "pkexec action lookup extension " PACKAGE_VERSION,
                                  0);
}

void
g_io_module_unload (GIOModule *module)
{
}
