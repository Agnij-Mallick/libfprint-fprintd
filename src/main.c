/*
 * fprint D-Bus daemon
 * Copyright (C) 2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2020 Marco Trevisan <marco.trevisan@canonical.com>
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

#define _GNU_SOURCE

#include "config.h"

#include <locale.h>
#include <poll.h>
#include <stdlib.h>

#include <gio/gio.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <fprint.h>
#include <glib-object.h>
#include <glib-unix.h>
#include <gmodule.h>

#include "fprintd.h"
#include "storage.h"
#include "file_storage.h"

#ifdef CONFIG_LIBFPRINT_PRIVATE
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#endif

fp_storage store;

static gboolean no_timeout = FALSE;
static gboolean g_fatal_warnings = FALSE;

static void
set_storage_file (void)
{
  store.init = &file_storage_init;
  store.deinit = &file_storage_deinit;
  store.print_data_save = &file_storage_print_data_save;
  store.print_data_load = &file_storage_print_data_load;
  store.print_data_delete = &file_storage_print_data_delete;
  store.discover_prints = &file_storage_discover_prints;
  store.discover_users = &file_storage_discover_users;
}

static gboolean
load_storage_module (const char *module_name)
{
  GModule *module;
  g_autofree char *filename = NULL;

  filename = g_module_build_path (PLUGINDIR, module_name);
  module = g_module_open (filename, 0);
  if (module == NULL)
    return FALSE;

  if (!g_module_symbol (module, "init", (gpointer *) &store.init) ||
      !g_module_symbol (module, "deinit", (gpointer *) &store.deinit) ||
      !g_module_symbol (module, "print_data_save", (gpointer *) &store.print_data_save) ||
      !g_module_symbol (module, "print_data_load", (gpointer *) &store.print_data_load) ||
      !g_module_symbol (module, "print_data_delete", (gpointer *) &store.print_data_delete) ||
      !g_module_symbol (module, "discover_prints", (gpointer *) &store.discover_prints))
    {
      g_module_close (module);
      return FALSE;
    }

  g_module_make_resident (module);

  return TRUE;
}

static gboolean
load_conf (void)
{
  g_autofree char *filename = NULL;
  g_autofree char *module_name = NULL;

  g_autoptr(GKeyFile) file = NULL;
  g_autoptr(GError) error = NULL;

  filename = g_build_filename (SYSCONFDIR, "fprintd.conf", NULL);
  file = g_key_file_new ();
  g_debug ("About to load configuration file '%s'", filename);
  if (!g_key_file_load_from_file (file, filename, G_KEY_FILE_NONE, &error))
    {
      g_warning ("Could not open \"%s\": %s\n", filename, error->message);
      return FALSE;
    }

  module_name = g_key_file_get_string (file, "storage", "type", &error);
  if (module_name == NULL)
    return FALSE;

  if (g_str_equal (module_name, "file"))
    {
      set_storage_file ();
      return TRUE;
    }

  return load_storage_module (module_name);
}

static const GOptionEntry entries[] = {
  {"g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, "Make all warnings fatal", NULL},
  {"no-timeout", 't', 0, G_OPTION_ARG_NONE, &no_timeout, "Do not exit after unused for a while", NULL},
  { NULL }
};

static gboolean
sigterm_callback (gpointer data)
{
  GMainLoop *loop = data;

  g_main_loop_quit (loop);
  return FALSE;
}

static void
on_name_acquired (GDBusConnection *connection,
                  const char      *name,
                  gpointer         user_data)
{
  g_debug ("D-Bus service launched with name: %s", name);
}

static void
on_name_lost (GDBusConnection *connection,
              const char      *name,
              gpointer         user_data)
{
  GMainLoop *loop = user_data;

  g_warning ("Failed to get name: %s", name);

  g_main_loop_quit (loop);
}

#ifdef CONFIG_LIBFPRINT_PRIVATE
static void
create_private_executable_copy (void *addr, size_t length)
{
  void *mapping = NULL;
  int memfd;

  /* memfd is more robust (and we can lock it down later). */
  memfd = memfd_create ("libfprint-copy", MFD_ALLOW_SEALING);
  if (memfd < 0)
    g_error ("Could not create memfd for libfprint code");

  if (ftruncate (memfd, length) < 0)
    g_error ("Could not set length of memfd");

  mapping = mmap (NULL, length, PROT_WRITE, MAP_SHARED, memfd, 0);
  if (mapping == MAP_FAILED)
    g_error ("Failed to mmap memfd to copy data");

  memcpy (mapping, addr, length);
  if (munmap (mapping, length) < 0)
    g_error ("Error unmapping area for copying libfprint code into");

  if (fcntl (memfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
    g_error ("Failed to seal memfd against modifications");

  mapping = mmap (addr, length, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, memfd, 0);
  if (mapping != addr)
    g_error ("Failed to mmap memfd as executable memory");

  close (memfd);
}

static int
dl_iterate_cb (struct dl_phdr_info *info, size_t size, void *data)
{
  void *addr;

  if (strstr (info->dlpi_name, "libfprint") == NULL)
    return 0;

  for (int j = 0; j < info->dlpi_phnum; j++)
    {
      if (info->dlpi_phdr[j].p_type != PT_LOAD)
        continue;

      if ((info->dlpi_phdr[j].p_flags & 0x1) != 0x1)
        continue;

      if (info->dlpi_phdr[j].p_flags != 0x5)
        g_error ("Found executable mapping that is not RX only.");

      addr = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
      create_private_executable_copy (addr, info->dlpi_phdr[j].p_memsz);

      *(size_t *) data += info->dlpi_phdr[j].p_memsz;
    }

  return 1;
}

static void
protect_libfprint (void)
{
  size_t protected_bytes = 0x0;

  dl_iterate_phdr (dl_iterate_cb, &protected_bytes);

  if (protected_bytes == 0)
    g_error ("The libfprint executable memory was not protected againts side-channel attacks");
}

static void
disable_memfd (void)
{
  static struct sock_filter filter[] = {
    /* [1] Load syscall number */
    BPF_STMT (BPF_LD | BPF_W | BPF_ABS,
              (offsetof (struct seccomp_data, nr))),

    /* [2] Test whether it is  */
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_memfd_create, 0, 1),

    /* [3] Kill process */
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    /* [4] Allow everything other than SYS_memfd_create */
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  static struct sock_fprog prog = {
    .len = G_N_ELEMENTS (filter),
    .filter = filter,
  };

  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if (syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
    g_error ("Could not install seccomp filter to prohibit memfd_create");
}
#endif

int
main (int argc, char **argv)
{
  g_autoptr(GOptionContext) context = NULL;
  g_autoptr(GMainLoop) loop = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(FprintManager) manager = NULL;
  g_autoptr(GDBusConnection) connection = NULL;
  guint32 request_name_ret;

#ifdef CONFIG_LIBFPRINT_PRIVATE
  protect_libfprint ();
  disable_memfd ();
#endif

  setlocale (LC_ALL, "");

  bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  textdomain (GETTEXT_PACKAGE);

  context = g_option_context_new ("Fingerprint handler daemon");
  g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

  if (g_option_context_parse (context, &argc, &argv, &error) == FALSE)
    {
      g_warning ("couldn't parse command-line options: %s\n", error->message);
      return 1;
    }

  if (g_fatal_warnings)
    {
      GLogLevelFlags fatal_mask;

      fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
      fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
      g_log_set_always_fatal (fatal_mask);
    }

  /* Obtain a connection to the system bus */
  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (!G_IS_DBUS_CONNECTION (connection))
    {
      g_warning ("Failed to open connection to bus: %s", error->message);
      return 1;
    }

  /* Load the configuration file,
   * and the default storage plugin */
  if (!load_conf ())
    set_storage_file ();
  store.init ();

  loop = g_main_loop_new (NULL, FALSE);
  g_unix_signal_add (SIGTERM, sigterm_callback, loop);

  g_debug ("Launching FprintObject");

  /* create the one instance of the Manager object to be shared between
   * all fprintd users. This blocks until all the devices are enumerated */
  manager = fprint_manager_new (connection, no_timeout);

  /* Obtain the well-known name after the manager has been initialized.
   * Otherwise a client immediately enumerating the devices will not see
   * any. */
  request_name_ret = g_bus_own_name_on_connection (connection,
                                                   FPRINT_SERVICE_NAME,
                                                   G_BUS_NAME_OWNER_FLAGS_NONE,
                                                   on_name_acquired,
                                                   on_name_lost,
                                                   loop, NULL);

  g_debug ("entering main loop");
  g_main_loop_run (loop);
  g_bus_unown_name (request_name_ret);
  g_debug ("main loop completed");

  store.deinit ();

  return 0;
}
