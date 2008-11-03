/*
 * /net/reactivated/Fprint/Manager object implementation
 * Copyright (C) 2008 Daniel Drake <dsd@gentoo.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unistd.h>
#include <stdlib.h>
#include <dbus/dbus-glib-bindings.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <libfprint/fprint.h>
#include <glib-object.h>

#include "fprintd.h"

static gboolean fprint_manager_get_devices(FprintManager *manager,
	GPtrArray **devices, GError **error);

#include "manager-dbus-glue.h"

static GObjectClass *parent_class = NULL;

G_DEFINE_TYPE(FprintManager, fprint_manager, G_TYPE_OBJECT);

typedef struct
{
	GError *last_error;
	GSList *dev_registry;
	guint timeout_id;
	volatile int num_device_used;
} FprintManagerPrivate;

#define FPRINT_MANAGER_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE ((o), FPRINT_TYPE_MANAGER, FprintManagerPrivate))

static void fprint_manager_finalize(GObject *object)
{
	FprintManagerPrivate *priv = FPRINT_MANAGER_GET_PRIVATE (object);

	g_slist_free(priv->dev_registry);
	if (priv->last_error)
		g_error_free (priv->last_error);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

static void fprint_manager_class_init(FprintManagerClass *klass)
{
	dbus_g_object_type_install_info(FPRINT_TYPE_MANAGER,
		&dbus_glib_fprint_manager_object_info);

	g_type_class_add_private ((GObjectClass *) klass, sizeof (FprintManagerPrivate));

	G_OBJECT_CLASS(klass)->finalize = fprint_manager_finalize;
	parent_class = g_type_class_peek_parent(klass);
}

static gchar *get_device_path(FprintDevice *rdev)
{
	return g_strdup_printf("/net/reactivated/Fprint/Device/%d",
		_fprint_device_get_id(rdev));
}

static gboolean
fprint_manager_timeout_cb (FprintManager *manager)
{
	g_message ("No devices in use, exit");
	//FIXME kill all the devices
	exit(0);
}

static void
fprint_manager_action_notified (FprintDevice *rdev, GParamSpec *spec, FprintManager *manager)
{
	FprintManagerPrivate *priv = FPRINT_MANAGER_GET_PRIVATE (manager);
	int action;

	g_object_get (G_OBJECT(rdev), "action", &action, NULL);
	if (priv->timeout_id > 0) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}
	if (action == 0) {
		if (g_atomic_int_dec_and_test (&priv->num_device_used)) {
			if (!no_timeout)
				priv->timeout_id = g_timeout_add_seconds (TIMEOUT, (GSourceFunc) fprint_manager_timeout_cb, manager);
		}
	} else {
		g_atomic_int_add (&priv->num_device_used, 1);
	}
}

static void
fprint_manager_init (FprintManager *manager)
{
	FprintManagerPrivate *priv = FPRINT_MANAGER_GET_PRIVATE (manager);
	struct fp_dscv_dev **discovered_devs = fp_discover_devs();
	struct fp_dscv_dev *ddev;
	int i = 0;

	priv->num_device_used = 0;

	if (!discovered_devs) {
		priv->last_error = g_error_new (FPRINT_ERROR, FPRINT_ERROR_INTERNAL,
						_("An internal error occurred in libfprint"));
		return;
	}

	dbus_g_connection_register_g_object(fprintd_dbus_conn,
		"/net/reactivated/Fprint/Manager", G_OBJECT(manager));

	while ((ddev = discovered_devs[i++]) != NULL) {
		FprintDevice *rdev = fprint_device_new(ddev);
		gchar *path;

		g_signal_connect (G_OBJECT(rdev), "notify::action",
				  G_CALLBACK (fprint_manager_action_notified), manager);

		priv->dev_registry = g_slist_prepend(priv->dev_registry, rdev);
		path = get_device_path(rdev);
		dbus_g_connection_register_g_object(fprintd_dbus_conn, path,
			G_OBJECT(rdev));
		g_free(path);
	}

	if (!no_timeout)
		priv->timeout_id = g_timeout_add_seconds (TIMEOUT, (GSourceFunc) fprint_manager_timeout_cb, manager);
}

FprintManager *fprint_manager_new(void)
{
	return g_object_new(FPRINT_TYPE_MANAGER, NULL);
}

GError *fprint_manager_get_error(FprintManager *manager)
{
	FprintManagerPrivate *priv = FPRINT_MANAGER_GET_PRIVATE (manager);

	if (priv->last_error == NULL)
		return NULL;

	return g_error_copy (priv->last_error);
}

static gboolean fprint_manager_get_devices(FprintManager *manager,
	GPtrArray **devices, GError **error)
{
	FprintManagerPrivate *priv = FPRINT_MANAGER_GET_PRIVATE (manager);
	GSList *elem = priv->dev_registry;
	int num_open = g_slist_length(elem);
	GPtrArray *devs = g_ptr_array_sized_new(num_open);

	if (num_open > 0)
		do {
			FprintDevice *rdev = elem->data;
			g_ptr_array_add(devs, get_device_path(rdev));
		} while ((elem = g_slist_next(elem)) != NULL);

	*devices = devs;
	return TRUE;
}

