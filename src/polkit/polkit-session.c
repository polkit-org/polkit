/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-session.c : sessions
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

#include "polkit-debug.h"
#include "polkit-session.h"
#include "polkit-utils.h"
#include "polkit-test.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-session
 * @title: Session
 * @short_description: Represents a ConsoleKit Session.
 *
 * This class is used to represent a session.
 **/

/**
 * PolKitSession:
 *
 * Objects of this class are used to record information about a
 * session.
 **/
struct _PolKitSession
{
        int refcount;
        uid_t uid;
        PolKitSeat *seat;
        char *ck_objref;
        polkit_bool_t is_active;
        polkit_bool_t is_local;
        char *remote_host;
};

/**
 * polkit_session_new:
 * 
 * Creates a new #PolKitSession object.
 * 
 * Returns: the new object
 **/
PolKitSession *
polkit_session_new (void)
{
        PolKitSession *session;
        session = kit_new0 (PolKitSession, 1);
        if (session == NULL)
                goto out;
        session->refcount = 1;
out:
        return session;
}

/**
 * polkit_session_ref:
 * @session: The session object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitSession *
polkit_session_ref (PolKitSession *session)
{
        kit_return_val_if_fail (session != NULL, session);
        session->refcount++;
        return session;
}


/**
 * polkit_session_unref:
 * @session: The session object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void 
polkit_session_unref (PolKitSession *session)
{
        kit_return_if_fail (session != NULL);
        session->refcount--;
        if (session->refcount > 0) 
                return;
        kit_free (session->ck_objref);
        kit_free (session->remote_host);
        if (session->seat != NULL)
                polkit_seat_unref (session->seat);
        kit_free (session);
}

/**
 * polkit_session_set_uid:
 * @session: The session object
 * @uid: UNIX user id
 * 
 * Set the UNIX user id of the user owning the session.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_uid (PolKitSession *session, uid_t uid)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        session->uid = uid;
        return TRUE;
}

/**
 * polkit_session_set_ck_objref:
 * @session: The session object
 * @ck_objref: D-Bus object path
 * 
 * Set the D-Bus object path to the ConsoleKit session object.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_ck_objref (PolKitSession *session, const char *ck_objref)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (_pk_validate_identifier (ck_objref), FALSE);
        if (session->ck_objref != NULL)
                kit_free (session->ck_objref);
        session->ck_objref = kit_strdup (ck_objref);
        if (session->ck_objref == NULL)
                return FALSE;
        else
                return TRUE;
}

/**
 * polkit_session_set_ck_is_active:
 * @session: The session object
 * @is_active: whether ConsoleKit reports the session as active
 * 
 * Set whether ConsoleKit regard the session as active.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_ck_is_active (PolKitSession *session, polkit_bool_t is_active)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        session->is_active = is_active;
        return TRUE;
}

/**
 * polkit_session_set_ck_is_local:
 * @session: The session object
 * @is_local: whether ConsoleKit reports the session as local
 * 
 * Set whether ConsoleKit regard the session as local.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_ck_is_local (PolKitSession *session, polkit_bool_t is_local)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        session->is_local = is_local;
        return TRUE;
}

/**
 * polkit_session_set_ck_remote_host:
 * @session: The session object
 * @remote_host: hostname of the host/display that ConsoleKit reports
 * the session to occur at
 * 
 * Set the remote host/display that ConsoleKit reports the session to
 * occur at.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_ck_remote_host (PolKitSession *session, const char *remote_host)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        /* TODO: FIXME: probably need to allow a lot more here */
        kit_return_val_if_fail (_pk_validate_identifier (remote_host), FALSE);
        if (session->remote_host != NULL)
                kit_free (session->remote_host);
        session->remote_host = kit_strdup (remote_host);
        if (session->remote_host == NULL)
                return FALSE;
        else
                return TRUE;
}

/**
 * polkit_session_set_seat:
 * @session: The session object
 * @seat: a #PolKitSeat object
 * 
 * Set the seat that the session belongs to. The reference count on
 * the given object will be increased by one. If an existing seat
 * object was set already, the reference count on that one will be
 * decreased by one.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_session_set_seat (PolKitSession *session, PolKitSeat *seat)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (polkit_seat_validate (seat), FALSE);
        if (session->seat != NULL)
                polkit_seat_unref (session->seat);
        session->seat = seat != NULL ? polkit_seat_ref (seat) : NULL;
        return TRUE;
}

/**
 * polkit_session_get_uid:
 * @session: The session object
 * @out_uid: UNIX user id
 * 
 * Get the UNIX user id of the user owning the session.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_uid (PolKitSession *session, uid_t *out_uid)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_uid != NULL, FALSE);
        *out_uid = session->uid;
        return TRUE;
}

/**
 * polkit_session_get_ck_objref:
 * @session: The session object
 * @out_ck_objref: D-Bus object path. Shall not be freed by the caller.
 * 
 * Get the D-Bus object path to the ConsoleKit session object.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_ck_objref (PolKitSession *session, char **out_ck_objref)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_ck_objref != NULL, FALSE);
        *out_ck_objref = session->ck_objref;
        return TRUE;
}

/**
 * polkit_session_get_ck_is_active:
 * @session: The session object
 * @out_is_active: whether ConsoleKit reports the session as active
 * 
 * Get whether ConsoleKit regard the session as active.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_ck_is_active (PolKitSession *session, polkit_bool_t *out_is_active)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_is_active != NULL, FALSE);
        *out_is_active = session->is_active;
        return TRUE;
}

/**
 * polkit_session_get_ck_is_local:
 * @session: The session object
 * @out_is_local: whether ConsoleKit reports the session as local
 * 
 * Set whether ConsoleKit regard the session as local.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_ck_is_local (PolKitSession *session, polkit_bool_t *out_is_local)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_is_local != NULL, FALSE);
        *out_is_local = session->is_local;
        return TRUE;
}

/**
 * polkit_session_get_ck_remote_host:
 * @session: The session object
 * @out_remote_host: hostname of the host/display that ConsoleKit
 * reports the session to occur at. Shall not be freed by the caller.
 * 
 * Get the remote host/display that ConsoleKit reports the session to
 * occur at.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_ck_remote_host (PolKitSession *session, char **out_remote_host)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_remote_host != NULL, FALSE);
        *out_remote_host = session->remote_host;
        return TRUE;
}

/**
 * polkit_session_get_seat:
 * @session: The session object
 * @out_seat: Returns the seat the session belongs to. Shall not
 * be unreffed by the caller.
 * 
 * Get the seat that the session belongs to.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_session_get_seat (PolKitSession *session, PolKitSeat **out_seat)
{
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_seat != NULL, FALSE);
        *out_seat = session->seat;
        return TRUE;
}

/**
 * polkit_session_debug:
 * @session: the object
 * 
 * Print debug details
 **/
void
polkit_session_debug (PolKitSession *session)
{
        kit_return_if_fail (session != NULL);
        _pk_debug ("PolKitSession: refcount=%d uid=%d objpath=%s is_active=%d is_local=%d remote_host=%s", 
                   session->refcount, session->uid,
                   session->ck_objref, session->is_active, session->is_local, session->remote_host);
        if (session->seat != NULL)
                polkit_seat_debug (session->seat);
}


/**
 * polkit_session_validate:
 * @session: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 **/
polkit_bool_t
polkit_session_validate (PolKitSession *session)
{
        polkit_bool_t ret;
        kit_return_val_if_fail (session != NULL, FALSE);

        ret = FALSE;
        if (session->is_local) {
                if (session->remote_host != NULL)
                        goto error;
        } else {
                if (session->remote_host == NULL)
                        goto error;
        }
        ret = TRUE;
error:
        return ret;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        char *str;
        PolKitSession *s;
        PolKitSeat *seat;
        PolKitSeat *seat2;
        uid_t uid;
        polkit_bool_t b;

        s = polkit_session_new ();
        if (s == NULL) {
                /* OOM */
        } else {
                if (! polkit_session_set_ck_objref (s, "/somesession")) {
                        /* OOM */
                } else {
                        kit_assert (polkit_session_get_ck_objref (s, &str) && strcmp (str, "/somesession") == 0);
                        polkit_session_ref (s);
                        polkit_session_unref (s);
                        polkit_session_debug (s);
                        if (! polkit_session_set_ck_objref (s, "/somesession2")) {
                                /* OOM */
                        } else {
                                kit_assert (polkit_session_get_ck_objref (s, &str) && strcmp (str, "/somesession2") == 0);
                        }

                        if ((seat = polkit_seat_new ()) != NULL) {
                                if (polkit_seat_set_ck_objref (seat, "/someseat")) {
                                        kit_assert (polkit_session_set_seat (s, seat));
                                        kit_assert (polkit_session_get_seat (s, &seat2) && seat == seat2);
                                }
                                polkit_seat_unref (seat);
                                if ((seat = polkit_seat_new ()) != NULL) {
                                        if (polkit_seat_set_ck_objref (seat, "/someseat2")) {
                                                kit_assert (polkit_session_set_seat (s, seat));
                                                kit_assert (polkit_session_get_seat (s, &seat2) && seat == seat2);
                                        }
                                        polkit_seat_unref (seat);
                                }
                        }

                        kit_assert (polkit_session_set_uid (s, 0));
                        kit_assert (polkit_session_get_uid (s, &uid) && uid == 0);
                        kit_assert (polkit_session_set_ck_is_active (s, TRUE));
                        kit_assert (polkit_session_get_ck_is_active (s, &b) && b == TRUE);
                        kit_assert (polkit_session_set_ck_is_local (s, TRUE));
                        kit_assert (polkit_session_get_ck_is_local (s, &b) && b == TRUE);
                        kit_assert (polkit_session_validate (s));

                        kit_assert (polkit_session_set_uid (s, 500));
                        kit_assert (polkit_session_get_uid (s, &uid) && uid == 500);
                        kit_assert (polkit_session_set_ck_is_active (s, FALSE));
                        kit_assert (polkit_session_get_ck_is_active (s, &b) && b == FALSE);
                        kit_assert (polkit_session_set_ck_is_local (s, FALSE));
                        kit_assert (polkit_session_get_ck_is_local (s, &b) && b == FALSE);

                        /* not valid because remote host is not set.. */
                        kit_assert (!polkit_session_validate (s));


                        if (polkit_session_set_ck_remote_host (s, "somehost.com")) {
                                kit_assert (polkit_session_get_ck_remote_host (s, &str) && strcmp (str, "somehost.com") == 0);
                                kit_assert (polkit_session_validate (s));

                                /* not valid because remote host is set and local==TRUE */
                                kit_assert (polkit_session_set_ck_is_local (s, TRUE));
                                kit_assert (!polkit_session_validate (s));
                                kit_assert (polkit_session_set_ck_is_local (s, FALSE));

                                if (polkit_session_set_ck_remote_host (s, "somehost2.com")) {
                                        kit_assert (polkit_session_get_ck_remote_host (s, &str) && strcmp (str, "somehost2.com") == 0);
                                        kit_assert (polkit_session_validate (s));
                                }
                                polkit_session_debug (s);
                        }

                }
                polkit_session_unref (s);
        }

        return TRUE;
}

KitTest _test_session = {
        "polkit_session",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */
