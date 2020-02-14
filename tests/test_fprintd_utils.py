#!/usr/bin/python3

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option) any
# later version.  See http://www.gnu.org/copyleft/lgpl.html for the full text
# of the license.

__author__ = 'Bastien Nocera'
__email__ = 'hadess@hadess.net'
__copyright__ = '(c) 2020 Red Hat Inc.'
__license__ = 'LGPL 3+'

import tempfile
import unittest
import sys
import subprocess
import dbus
import dbus.mainloop.glib
import dbusmock
import fcntl
import os
import time

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

class TestFprintd(dbusmock.DBusTestCase):
    '''Test fprintd utilities'''

    @classmethod
    def setUpClass(klass):
        klass.start_system_bus()
        klass.dbus_con = klass.get_dbus(True)
        klass.sleep_time = 0.5

        template_path = './'
        if 'TOPSRCDIR' in os.environ:
            template_path = os.environ['TOPSRCDIR'] + '/tests/'
        klass.template_name = template_path + 'dbusmock/fprintd.py'
        print ('Using template from %s' % klass.template_name)

        klass.tools_prefix = ''
        if 'FPRINT_BUILD_DIR' in os.environ:
            klass.tools_prefix = os.environ['FPRINT_BUILD_DIR'] + '/../utils/'
            print ('Using tools from %s' % klass.tools_prefix)
        else:
            print ('Using tools from $PATH')

        klass.wrapper_args = []
        klass.valgrind = False
        if 'VALGRIND' in os.environ:
            valgrind = os.environ['VALGRIND']
            if valgrind is not None:
                klass.valgrind = True
                klass.sleep_time *= 4
                klass.wrapper_args = ['valgrind', '--leak-check=full']
                if os.path.exists(valgrind):
                    klass.wrapper_args += ['--suppressions={}'.format(valgrind)]

        if 'ADDRESS_SANITIZER' in os.environ:
            klass.sleep_time *= 2

    def setUp(self):
        (self.p_mock, self.obj_fprintd_manager) = self.spawn_server_template(
            self.template_name, {}, stdout=subprocess.PIPE)
        # set log to nonblocking
        flags = fcntl.fcntl(self.p_mock.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.p_mock.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.obj_fprintd_mock = dbus.Interface(self.obj_fprintd_manager, 'net.reactivated.Fprint.Manager.Mock')

    def tearDown(self):
        self.p_mock.terminate()
        self.p_mock.wait()

    def setup_device(self):
        device_path = self.obj_fprintd_mock.AddDevice('FDO Trigger Finger Laser Reader', 3, 'swipe')
        self.device_mock = self.dbus_con.get_object('net.reactivated.Fprint', device_path)
        self.device_mock.SetEnrolledFingers('toto', ['left-little-finger', 'right-little-finger'])

    def start_utility_process(self, utility_name, args=[], sleep=True):
        utility = [ os.path.join(self.tools_prefix, 'fprintd-{}'.format(utility_name)) ]
        process = subprocess.Popen(self.wrapper_args + utility + args,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   universal_newlines=True)
        flags = fcntl.fcntl(process.stdout, fcntl.F_GETFL)
        fcntl.fcntl(process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self.addCleanup(lambda: print(process.stdout.read()))
        self.addCleanup(process.terminate)
        self.addCleanup(process.wait)

        if sleep:
            time.sleep(self.sleep_time)

        return process

    def get_process_output(self, process):
        out = process.stdout.read()
        self.addCleanup(print, out)
        return out

    def run_utility_process(self, utility_name, args=[], sleep=True, timeout=None):
        proc = self.start_utility_process(utility_name, args=args, sleep=sleep)
        ret = proc.wait(timeout=timeout if timeout is not None else self.sleep_time * 4)
        self.assertLessEqual(ret, 128)

        return self.get_process_output(proc)

    def test_fprintd_enroll(self):
        self.setup_device()

        process = self.start_utility_process('enroll', ['-f', 'right-index-finger', 'toto'])

        out = self.get_process_output(process)
        self.assertRegex(out, r'right-index-finger')

        self.device_mock.EmitEnrollStatus('enroll-completed', True)
        time.sleep(self.sleep_time)

        out = self.get_process_output(process)
        self.assertRegex(out, 'Enroll result: enroll-completed')

    def test_fprintd_verify(self):
        self.setup_device()

        process = self.start_utility_process('verify', ['toto'])

        out = self.get_process_output(process)
        self.assertRegex(out, r'left-little-finger')
        self.assertNotRegex(out, 'Verify result: verify-match \(done\)')

        self.device_mock.EmitVerifyStatus('verify-match', True)
        time.sleep(self.sleep_time)

        out = self.get_process_output(process)
        self.assertRegex(out, 'Verify result: verify-match \(done\)')

    def test_fprintd_verify_script(self):
        self.setup_device()
        script = [
            ( 'verify-match', True, 2 )
        ]
        self.device_mock.SetVerifyScript(script)

        process = self.start_utility_process('verify', ['toto'])

        out = self.get_process_output(process)
        self.assertRegex(out, r'left-little-finger')
        self.assertNotRegex(out, 'Verify result: verify-match \(done\)')

        time.sleep(self.sleep_time * 4)

        out = self.get_process_output(process)
        self.assertRegex(out, 'Verify result: verify-match \(done\)')

    def test_fprintd_list(self):
        self.setup_device()

        # Rick has no fingerprints enrolled
        out = self.run_utility_process('list', ['rick'])
        self.assertRegex(out, r'has no fingers enrolled for')

        # Toto does
        out = self.run_utility_process('list', ['toto'])
        self.assertRegex(out, r'right-little-finger')

    def test_fprintd_delete(self):
        self.setup_device()

        # Has fingerprints enrolled
        out = self.run_utility_process('list', ['toto'])
        self.assertRegex(out, r'left-little-finger')
        self.assertRegex(out, r'right-little-finger')

        # Delete fingerprints
        out = self.run_utility_process('delete', ['toto'])
        self.assertRegex(out, r'Fingerprints deleted')

        # Doesn't have fingerprints
        out = self.run_utility_process('list', ['toto'])
        self.assertRegex(out, r'has no fingers enrolled for')

if __name__ == '__main__':
    # avoid writing to stderr
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
