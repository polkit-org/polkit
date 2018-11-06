/*
 * Copyright (C) 2008-2010 Red Hat, Inc.
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
 * Author: Matthias Clasen <mclasen@redhat.com>
 *         David Zeuthen <davidz@redhat.com>
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>

#include <gio/gio.h>
#include "polkitpermission.h"
#include <polkit/polkit.h>

#include "polkitpermission.h"

/**
 * SECTION:polkitpermission
 * @title: PolkitPermission
 * @short_description: PolicyKit #GPermission implementation
 * @stability: Stable
 *
 * #PolkitPermission is a #GPermission implementation. It can be used
 * with e.g. #GtkLockButton. See the #GPermission documentation for
 * more information.
 */

typedef GPermissionClass PolkitPermissionClass;

/**
 * PolkitPermission:
 *
 * The #PolkitPermission struct should not be accessed directly.
 */
struct _PolkitPermission
{
  GPermission parent_instance;

  PolkitAuthority *authority;
  PolkitSubject *subject;

  gchar *action_id;

  /* non-NULL exactly when authorized with a temporary authorization */
  gchar *tmp_authz_id;
};

enum
{
  PROP_0,
  PROP_ACTION_ID,
  PROP_SUBJECT
};

static void process_result (PolkitPermission          *permission,
                            PolkitAuthorizationResult *result);

static void on_authority_changed (PolkitAuthority *authority,
                                  gpointer         user_data);

static gboolean acquire        (GPermission          *permission,
                                GCancellable         *cancellable,
                                GError              **error);
static void     acquire_async  (GPermission          *permission,
                                GCancellable         *cancellable,
                                GAsyncReadyCallback   callback,
                                gpointer              user_data);
static gboolean acquire_finish (GPermission          *permission,
                                GAsyncResult         *result,
                                GError              **error);

static gboolean release        (GPermission          *permission,
                                GCancellable         *cancellable,
                                GError              **error);
static void     release_async  (GPermission          *permission,
                                GCancellable         *cancellable,
                                GAsyncReadyCallback   callback,
                                gpointer              user_data);
static gboolean release_finish (GPermission          *permission,
                                GAsyncResult         *result,
                                GError              **error);

static void initable_iface_init       (GInitableIface *initable_iface);
static void async_initable_iface_init (GAsyncInitableIface *async_initable_iface);

static gboolean polkit_permission_initable_init (GInitable     *initable,
                                                 GCancellable  *cancellable,
                                                 GError       **error);

G_DEFINE_TYPE_WITH_CODE (PolkitPermission, polkit_permission, G_TYPE_PERMISSION,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, async_initable_iface_init))


static void
polkit_permission_init (PolkitPermission *simple)
{
}

static void
polkit_permission_constructed (GObject *object)
{
  PolkitPermission *permission = POLKIT_PERMISSION (object);

  if (permission->subject == NULL)
    permission->subject = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());

  if (G_OBJECT_CLASS (polkit_permission_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (polkit_permission_parent_class)->constructed (object);
}

static void
polkit_permission_finalize (GObject *object)
{
  PolkitPermission *permission = POLKIT_PERMISSION (object);

  g_free (permission->action_id);
  g_free (permission->tmp_authz_id);
  g_object_unref (permission->subject);

  if (permission->authority != NULL)
    {
      g_signal_handlers_disconnect_by_func (permission->authority,
                                            on_authority_changed,
                                            permission);
      g_object_unref (permission->authority);
    }

  if (G_OBJECT_CLASS (polkit_permission_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_permission_parent_class)->finalize (object);
}

static void
polkit_permission_get_property (GObject    *object,
                                guint       property_id,
                                GValue     *value,
                                GParamSpec *pspec)
{
  PolkitPermission *permission = POLKIT_PERMISSION (object);

  switch (property_id)
    {
    case PROP_ACTION_ID:
      g_value_set_string (value, permission->action_id);
      break;

    case PROP_SUBJECT:
      g_value_set_object (value, permission->subject);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
    }
}

static void
polkit_permission_set_property (GObject      *object,
                                guint         property_id,
                                const GValue *value,
                                GParamSpec   *pspec)
{
  PolkitPermission *permission = POLKIT_PERMISSION (object);

  switch (property_id)
    {
    case PROP_ACTION_ID:
      permission->action_id = g_value_dup_string (value);
      break;

    case PROP_SUBJECT:
      permission->subject = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
    }
}

static void
polkit_permission_class_init (PolkitPermissionClass *class)
{
  GObjectClass *object_class;
  GPermissionClass *permission_class;

  permission_class = G_PERMISSION_CLASS (class);
  permission_class->acquire = acquire;
  permission_class->acquire_async = acquire_async;
  permission_class->acquire_finish = acquire_finish;
  permission_class->release = release;
  permission_class->release_async = release_async;
  permission_class->release_finish = release_finish;

  object_class = G_OBJECT_CLASS (class);
  object_class->finalize = polkit_permission_finalize;
  object_class->constructed = polkit_permission_constructed;
  object_class->get_property = polkit_permission_get_property;
  object_class->set_property = polkit_permission_set_property;

  /**
   * PolkitPermission:action-id:
   *
   * The action identifier to use for the permission.
   */
  g_object_class_install_property (object_class,
                                   PROP_ACTION_ID,
                                   g_param_spec_string ("action-id",
                                                        "Action Identifier",
                                                        "The action identifier to use for the permission",
                                                        NULL,
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_STATIC_STRINGS));
  /**
   * PolkitPermission:subject:
   *
   * The #PolkitSubject to use for the permission. If not set during
   * construction, it will be set to match the current process.
   */
  g_object_class_install_property (object_class,
                                   PROP_SUBJECT,
                                   g_param_spec_object ("subject",
                                                        "Subject",
                                                        "The subject to use for the permission",
                                                        POLKIT_TYPE_SUBJECT,
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_STATIC_STRINGS));
}

/**
 * polkit_permission_new:
 * @action_id: The PolicyKit action identifier.
 * @subject: (allow-none): A #PolkitSubject or %NULL for the current process.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Creates a #GPermission instance for the PolicyKit action
 * @action_id.
 *
 * When the operation is finished, @callback will be invoked. You can
 * then call polkit_permission_new_finish() to get the result of the
 * operation.
 *
 * This is a asynchronous failable constructor. See
 * polkit_permission_new_sync() for the synchronous version.
 */
void
polkit_permission_new (const gchar         *action_id,
                       PolkitSubject       *subject,
                       GCancellable        *cancellable,
                       GAsyncReadyCallback  callback,
                       gpointer             user_data)
{
  g_return_if_fail (action_id != NULL);
  g_return_if_fail (subject == NULL || POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_async_initable_new_async (POLKIT_TYPE_PERMISSION,
                              G_PRIORITY_DEFAULT,
                              cancellable,
                              callback,
                              user_data,
                              "action-id", action_id,
                              "subject", subject,
                              NULL);
}

/**
 * polkit_permission_new_finish:
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to polkit_permission_new().
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes an operation started with polkit_permission_new().
 *
 * Returns: A #GPermission or %NULL if @error is set.
 */
GPermission *
polkit_permission_new_finish (GAsyncResult  *res,
                              GError       **error)
{
  GObject *object;
  GObject *source_object;

  g_return_val_if_fail (G_IS_ASYNC_RESULT (res), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  source_object = g_async_result_get_source_object (res);
  g_assert (source_object != NULL);
  object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
                                        res,
                                        error);
  g_object_unref (source_object);
  if (object != NULL)
    return G_PERMISSION (object);
  else
    return NULL;
}

/**
 * polkit_permission_new_sync:
 * @action_id: The PolicyKit action identifier.
 * @subject: (allow-none): A #PolkitSubject or %NULL for the current process.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Creates a #GPermission instance for the PolicyKit action
 * @action_id.
 *
 * This is a synchronous failable constructor. See
 * polkit_permission_new() for the asynchronous version.
 *
 * Returns: A #GPermission or %NULL if @error is set.
 */
GPermission *
polkit_permission_new_sync (const gchar    *action_id,
                            PolkitSubject  *subject,
                            GCancellable   *cancellable,
                            GError        **error)
{
  g_return_val_if_fail (action_id != NULL, NULL);
  g_return_val_if_fail (subject == NULL || POLKIT_IS_SUBJECT (subject), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  return g_initable_new (POLKIT_TYPE_PERMISSION,
                         cancellable,
                         error,
                         "action-id", action_id,
                         "subject", subject,
                         NULL);
}

static void
initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = polkit_permission_initable_init;
}

static void
async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
  /* for now, we use default implementation to run GInitable code in a
   * thread - would probably be nice to have real async version to
   * avoid the thread-overhead
   */
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_permission_get_action_id:
 * @permission: A #PolkitPermission.
 *
 * Gets the PolicyKit action identifier used for @permission.
 *
 * Returns: A string owned by @permission. Do not free.
 */
const gchar *
polkit_permission_get_action_id (PolkitPermission *permission)
{
  g_return_val_if_fail (POLKIT_IS_PERMISSION (permission), NULL);
  return permission->action_id;
}

/**
 * polkit_permission_get_subject:
 * @permission: A #PolkitPermission.
 *
 * Gets the subject used for @permission.
 *
 * Returns: (transfer none): An object owned by @permission. Do not free.
 */
PolkitSubject *
polkit_permission_get_subject   (PolkitPermission    *permission)
{
  g_return_val_if_fail (POLKIT_IS_PERMISSION (permission), NULL);
  return permission->subject;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_permission_initable_init (GInitable     *initable,
                                 GCancellable  *cancellable,
                                 GError       **error)
{
  PolkitPermission *permission = POLKIT_PERMISSION (initable);
  PolkitAuthorizationResult *result;
  gboolean ret;

  ret = FALSE;

  permission->authority = polkit_authority_get_sync (cancellable, error);
  if (permission->authority == NULL)
    goto out;

  g_signal_connect (permission->authority,
                    "changed",
                    G_CALLBACK (on_authority_changed),
                    permission);

  result = polkit_authority_check_authorization_sync (permission->authority,
                                                      permission->subject,
                                                      permission->action_id,
                                                      NULL, /* PolkitDetails */
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                                      cancellable,
                                                      error);
  if (result == NULL)
    goto out;

  process_result (permission, result);
  g_object_unref (result);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
changed_check_cb (GObject       *source_object,
                  GAsyncResult  *res,
                  gpointer       user_data)
{
  PolkitPermission *permission = POLKIT_PERMISSION (user_data);
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_authority_check_authorization_finish (permission->authority,
                                                        res,
                                                        &error);
  if (result != NULL)
    {
      process_result (permission, result);
      g_object_unref (result);
    }
  else
    {
      /* this really should never fail (since we are not passing any
       * details) so log to stderr if it happens
       */
      g_warning ("Error checking authorization for action id %s: %s",
                 permission->action_id,
                 error->message);
      g_error_free (error);
    }
  g_object_unref (permission);
}

static void
on_authority_changed (PolkitAuthority *authority,
                      gpointer         user_data)
{
  PolkitPermission *permission = POLKIT_PERMISSION (user_data);

  polkit_authority_check_authorization (permission->authority,
                                        permission->subject,
                                        permission->action_id,
                                        NULL, /* PolkitDetails */
                                        POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                        NULL /* cancellable */,
                                        changed_check_cb,
                                        g_object_ref (permission));
}

static void
process_result (PolkitPermission          *permission,
                PolkitAuthorizationResult *result)
{
  gboolean can_acquire;
  gboolean can_release;
  gboolean allowed;

  /* save the temporary authorization id */
  g_free (permission->tmp_authz_id);
  permission->tmp_authz_id = g_strdup (polkit_authorization_result_get_temporary_authorization_id (result));
  allowed = polkit_authorization_result_get_is_authorized (result);
  if (permission->tmp_authz_id != NULL)
    {
      can_acquire = FALSE;
      can_release = TRUE;
    }
  else
    {
      if (allowed)
        can_acquire = FALSE;
      else
        can_acquire = polkit_authorization_result_get_retains_authorization (result);
      can_release = FALSE;
    }
  g_permission_impl_update (G_PERMISSION (permission), allowed, can_acquire, can_release);
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitPermission *permission;
  GSimpleAsyncResult *simple;
} AcquireData;

static void
acquire_data_free (AcquireData *data)
{
  g_object_unref (data->simple);
  g_free (data);
}

static void
acquire_cb (GObject      *source_object,
            GAsyncResult *res,
            gpointer      user_data)
{
  AcquireData *data = user_data;
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_authority_check_authorization_finish (data->permission->authority,
                                                        res,
                                                        &error);
  if (result != NULL)
    {
      /* Process the result such that allowed, can_acquire and
       * can_release are updated before returning to the user - see
       * also release_cb for where we do this as well
       */
      process_result (data->permission, result);
      if (!polkit_authorization_result_get_is_authorized (result))
        {
          if (polkit_authorization_result_get_dismissed (result))
            {
              g_simple_async_result_set_error (data->simple,
                                               G_IO_ERROR,
                                               G_IO_ERROR_CANCELLED,
                                               "User dismissed authentication dialog while trying to acquire permission for action-id %s",
                                               data->permission->action_id);
            }
          else
            {
              g_simple_async_result_set_error (data->simple,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_FAILED,
                                               "Failed to acquire permission for action-id %s",
                                               data->permission->action_id);
            }
        }
      g_object_unref (result);
    }
  else
    {
      g_simple_async_result_set_from_error (data->simple, error);
      g_error_free (error);
    }
  /* don't complete in idle since we're already completing in idle
   * due to how PolkitAuthority works
   */
  g_simple_async_result_complete (data->simple);
  acquire_data_free (data);
}

static void
acquire_async (GPermission         *gpermission,
               GCancellable        *cancellable,
               GAsyncReadyCallback  callback,
               gpointer             user_data)
{
  PolkitPermission *permission = POLKIT_PERMISSION (gpermission);
  AcquireData *data;

  data = g_new0 (AcquireData, 1);
  data->permission = permission;
  data->simple = g_simple_async_result_new (G_OBJECT (permission),
                                            callback,
                                            user_data,
                                            acquire_async);

  polkit_authority_check_authorization (permission->authority,
                                        permission->subject,
                                        permission->action_id,
                                        NULL, /* PolkitDetails */
                                        POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                        cancellable,
                                        acquire_cb,
                                        data);
}

static gboolean
acquire_finish (GPermission   *gpermission,
                GAsyncResult  *result,
                GError       **error)
{
  GSimpleAsyncResult *simple;

  simple = G_SIMPLE_ASYNC_RESULT (result);
  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == acquire_async);

  if (g_simple_async_result_propagate_error (simple, error))
    return FALSE;

  return TRUE;
}

static gboolean
acquire (GPermission   *gpermission,
         GCancellable  *cancellable,
         GError       **error)
{
  PolkitPermission *permission = POLKIT_PERMISSION (gpermission);
  PolkitAuthorizationResult *result;
  gboolean ret;

  ret = FALSE;

  result = polkit_authority_check_authorization_sync (permission->authority,
                                                      permission->subject,
                                                      permission->action_id,
                                                      NULL, /* PolkitDetails */
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                      cancellable,
                                                      error);
  if (result != NULL)
    {
      /* need to update allowed, can_acquire, can_release before returning to the user */
      process_result (permission, result);
      if (polkit_authorization_result_get_is_authorized (result))
        {
          ret = TRUE;
        }
      else if (polkit_authorization_result_get_dismissed (result))
        {
          g_set_error (error,
                       G_IO_ERROR,
                       G_IO_ERROR_CANCELLED,
                       "User dismissed authentication dialog while trying to acquire permission for action-id %s",
                       permission->action_id);
        }
      else
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Failed to acquire permission for action-id %s",
                       permission->action_id);
        }
      g_object_unref (result);
    }

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitPermission *permission;
  GSimpleAsyncResult *simple;
} ReleaseData;

static void
release_data_free (ReleaseData *data)
{
  g_object_unref (data->simple);
  g_free (data);
}

static void
release_check_cb (GObject      *source_object,
                  GAsyncResult *res,
                  gpointer      user_data)
{
  ReleaseData *data = user_data;
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_authority_check_authorization_finish (data->permission->authority,
                                                        res,
                                                        &error);
  if (result == NULL)
    {
      g_prefix_error (&error,
                      "Error checking authorization for action id %s after releasing the permission: ",
                      data->permission->action_id);
      g_simple_async_result_set_from_error (data->simple, error);
      g_error_free (error);
    }
  else
    {
      process_result (data->permission, result);
      g_object_unref (result);
    }
  /* don't complete in idle since we're already completing in idle
   * due to how PolkitAuthority works
   */
  g_simple_async_result_complete (data->simple);
  release_data_free (data);
}

static void
release_cb (GObject      *source_object,
            GAsyncResult *res,
            gpointer      user_data)
{
  ReleaseData *data = user_data;
  GError *error;
  gboolean ret;

  ret = FALSE;

  error = NULL;
  ret = polkit_authority_revoke_temporary_authorization_by_id_finish (data->permission->authority,
                                                                      res,
                                                                      &error);
  if (!ret)
    {
      g_simple_async_result_set_from_error (data->simple, error);
      g_error_free (error);
      /* don't complete in idle since we're already completing in idle
       * due to how PolkitAuthority works
       */
      g_simple_async_result_complete (data->simple);
      release_data_free (data);
    }
  else
    {
      /* need to update allowed, can_acquire and can_release before
       * returning to the user - see also acquire_cb where we do this
       * as well
       */
      polkit_authority_check_authorization (data->permission->authority,
                                            data->permission->subject,
                                            data->permission->action_id,
                                            NULL, /* PolkitDetails */
                                            POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                            NULL /* cancellable */,
                                            release_check_cb,
                                            data);
    }
}

static void
release_async (GPermission         *gpermission,
               GCancellable        *cancellable,
               GAsyncReadyCallback  callback,
               gpointer             user_data)
{
  PolkitPermission *permission = POLKIT_PERMISSION (gpermission);
  ReleaseData *data;

  data = g_new0 (ReleaseData, 1);
  data->permission = permission;
  data->simple = g_simple_async_result_new (G_OBJECT (permission),
                                            callback,
                                            user_data,
                                            release_async);

  if (permission->tmp_authz_id == NULL)
    {
      g_simple_async_result_set_error (data->simple,
                                       POLKIT_ERROR,
                                       POLKIT_ERROR_FAILED,
                                       "Cannot release permission: no temporary authorization for action-id %s exist",
                                       permission->action_id);
      g_simple_async_result_complete_in_idle (data->simple);
      release_data_free (data);
      goto out;
    }

  polkit_authority_revoke_temporary_authorization_by_id (permission->authority,
                                                         permission->tmp_authz_id,
                                                         cancellable,
                                                         release_cb,
                                                         data);
 out:
  ;
}

static gboolean
release_finish (GPermission   *gpermission,
                GAsyncResult  *result,
                GError       **error)
{
  GSimpleAsyncResult *simple;

  simple = G_SIMPLE_ASYNC_RESULT (result);
  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == release_async);

  if (g_simple_async_result_propagate_error (simple, error))
    return FALSE;

  return TRUE;
}

static gboolean
release (GPermission   *gpermission,
         GCancellable  *cancellable,
         GError       **error)
{
  PolkitPermission *permission = POLKIT_PERMISSION (gpermission);
  PolkitAuthorizationResult *result;
  gboolean ret;

  ret = FALSE;

  if (permission->tmp_authz_id == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot release permission: no temporary authorization for action-id %s exist",
                   permission->action_id);
      goto out;
    }

  ret = polkit_authority_revoke_temporary_authorization_by_id_sync (permission->authority,
                                                                    permission->tmp_authz_id,
                                                                    cancellable,
                                                                    error);
  if (!ret)
    goto out;

  /* need to update allowed, can_acquire, can_release before returning to the user */
  result = polkit_authority_check_authorization_sync (permission->authority,
                                                      permission->subject,
                                                      permission->action_id,
                                                      NULL, /* PolkitDetails */
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                                      cancellable,
                                                      error);
  if (result == NULL)
    goto out;
  process_result (permission, result);
  g_object_unref (result);

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */
