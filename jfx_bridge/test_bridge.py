# -*- coding: utf-8 -*-
from __future__ import unicode_literals  # string literals are all unicode
from __future__ import division  # if python 2, force truediv division (default in 3)

import base64
import logging
import unittest
import uuid
import time
import sys
import os

from . import bridge

if sys.version_info[0] == 2:
    from socket import error as ConnectionRefusedError  # ConnectionRefusedError not defined in python2, this is next closest thing


class TestBridge(unittest.TestCase):
    """ Assumes there's a bridge server running at DEFAULT_SERVER_PORT """

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        TestBridge.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG)

    def test_import(self):

        mod = TestBridge.test_bridge.remote_import("base64")
        self.assertTrue(mod is not None)

    def test_call_no_args(self):

        mod = TestBridge.test_bridge.remote_import("uuid")

        result = mod.uuid4()

        self.assertTrue(result is not None)

    def test_call_arg(self):
        # also tests call with bytestring arg in python3

        mod = TestBridge.test_bridge.remote_import("base64")

        test_str = str(uuid.uuid4())

        result_str = None
        if sys.version[0] == "3":
            result = mod.b64encode(test_str.encode("utf-8"))
            result_str = base64.b64decode(result).decode("utf-8")
        else:
            # python2 can't send a byte string, and if the other end is python3, b64encode won't work on a string.
            # instead we'll try creating a uuid from the string
            remote_uuid = TestBridge.test_bridge.remote_import("uuid")
            new_uuid = remote_uuid.UUID(test_str)
            result_str = str(new_uuid)

        self.assertEqual(test_str, result_str)

    def test_call_multi_args(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo", mod.IGNORECASE)

        self.assertTrue(remote_obj is not None)

        self.assertTrue(remote_obj.match("FOO") is not None)

    def test_call_with_remote_obj(self):

        mod = TestBridge.test_bridge.remote_import("uuid")

        remote_obj = mod.uuid4()
        result = str(remote_obj)
        self.assertTrue(result is not None)
        self.assertTrue("-" in result and "4" in result)

    def test_call_with_str(self):
        """ also tests calling str() on remote obj """

        mod = TestBridge.test_bridge.remote_import("uuid")

        test_uuid_str = "00010203-0405-0607-0809-0a0b0c0d0e0f"

        remote_uuid = mod.UUID(test_uuid_str)
        self.assertTrue(remote_uuid is not None)
        result = str(remote_uuid)
        self.assertEqual(test_uuid_str, result)

    # bool, int, list, tuple, dict, bytes, bridge object, callback, exception, none
    # set a function into the remote __main__/globals() to call
    # callback as key func in list.sort

    def test_call_kwargs(self):
        self.skipTest("Not implemented yet")

    def test_get(self):
        mod = TestBridge.test_bridge.remote_import("uuid")
        remote_doc = mod.__doc__
        self.assertTrue("RFC 4122" in remote_doc)

    def test_set(self):
        test_string = "hello world"
        mod = TestBridge.test_bridge.remote_import("__main__")
        mod.test = test_string

        self.assertEqual(test_string, mod.test)

    def test_get_non_existent(self):
        """ Check that requesting a non-existent attribute over the bridge raises an attributeerror """
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        with self.assertRaises(AttributeError):
            remote_obj.doesnt_exist

    def test_get_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search
        self.assertTrue(isinstance(remote_callable, bridge.BridgedCallable))

    def test_callable(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.match

        self.assertTrue(remote_callable("fooa") is not None)

    def test_serialize_deserialize_types(self):
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        # assemble a list of different types
        # Note: we include False now to detect failure to correctly unpack "False" strings into bools
        test_list = [1, 0xFFFFFFFF, True, False, "string", "unicode_string🐉🔍",
                     (1, 2, 3), [4, 5, 6], {7: 8, 9: 10}, uuid.uuid4(), pow, 1.5]

        # gross hack - race where remote objects are being deleted after the remote list is created,
        # but before the response makes it back (so remote del commands arrive first and nuke the
        # handles). TODO - look into an actual fix, like keep handles until their local objects are
        # deleted as well?
        time.sleep(1)
        # send the list in to create a remote list (which comes straight back)
        created_list = remote_list(test_list)

        # check it's the same
        self.assertEqual(test_list, created_list)

    def test_serialize_deserialize_bytes(self):
        """ byte strings across 2<->3 bridges will be forced to strings (because py2 treats bytes and strs as the same thing """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        test_list = [b"bytes"]

        # send the list in to create a remote list (which comes straight back)s
        created_list = remote_list(test_list)

        # check it's the same, either as a byte or normal string
        self.assertTrue(created_list[0] == test_list[0]
                        or created_list[0] == test_list[0].decode("utf-8"))

    def test_serialize_deserialize_bridge_object(self):
        # bridge objects TODO
        self.skipTest("Not implemented yet")

    def test_none_result(self):
        mod = TestBridge.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search

        self.assertTrue(remote_callable("abar") is None)

    def test_exception(self):
        self.skipTest("Not implemented yet")

    def test_callback(self):
        """ Test we correctly handle calling back to here from across the bridge """
        def sort_fn(val):
            return len(val)

        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_sorted = mod.__builtins__.sorted

        test_list = ["aaa", "bb", "c"]
        sorted_list = remote_sorted(test_list, key=sort_fn)

        self.assertEqual(sorted(test_list, key=sort_fn), sorted_list)

    def test_remote_iterable(self):
        """ Test we can access values from a remote iterable """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)

        it_values = list(remote_it)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    def test_remote_iterable_for(self):
        """ Test we can access values from a remote iterable with a for loop """
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)
        it_values = list()
        for value in remote_it:
            it_values.append(value)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    def test_float(self):
        """ Test we can sent a float value """
        remote_time = TestBridge.test_bridge.remote_import("time")
        remote_time.sleep(0.1)

    def test_is_bridged_object(self):
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")

        remote_obj = remote_uuid.uuid4()
        local_obj = uuid.uuid4()

        self.assertTrue(bridge._is_bridged_object(remote_obj))
        self.assertFalse(bridge._is_bridged_object(local_obj))

    def test_bridged_isinstance(self):
        mod = TestBridge.test_bridge.remote_import("__main__")
        remote_float = mod.__builtins__.float
        remote_int = mod.__builtins__.int
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")
        remote_class = remote_uuid.UUID
        remote_obj = remote_uuid.uuid4()
        local_class = uuid.UUID
        local_obj = uuid.uuid4()

        # local obj, local class
        self.assertTrue(bridge.bridged_isinstance(local_obj, local_class))
        self.assertFalse(bridge.bridged_isinstance(local_obj, float))

        # local obj, fully local tuple
        self.assertTrue(bridge.bridged_isinstance(
            local_obj, (float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(local_obj, (float, int)))

        # local obj, mixed tuple
        self.assertTrue(bridge.bridged_isinstance(
            local_obj, (remote_class, float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(
            local_obj, (remote_float, float, int)))

        # local obj, remote class
        self.assertFalse(bridge.bridged_isinstance(local_obj, remote_class))

        # local obj, fully remote tuple
        self.assertFalse(bridge.bridged_isinstance(
            local_obj, (remote_float, remote_class)))

        # remote obj, local class
        self.assertFalse(bridge.bridged_isinstance(remote_obj, local_class))

        # remote obj, fully local tuple
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (float, local_class)))

        # remote obj, mixed tuple
        self.assertTrue(bridge.bridged_isinstance(
            remote_obj, (remote_class, float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (remote_float, float, int)))

        # remote obj, remote class
        self.assertTrue(bridge.bridged_isinstance(remote_obj, remote_class))
        self.assertFalse(bridge.bridged_isinstance(remote_obj, remote_float))

        # remote obj, fully remote tuple
        self.assertTrue(bridge.bridged_isinstance(
            remote_obj, (remote_float, remote_class)))
        self.assertFalse(bridge.bridged_isinstance(
            remote_obj, (remote_float, remote_int)))

    def test_bridged_get_type(self):
        """ Make sure we can get an object representing the type of a bridged object """
        remote_uuid = TestBridge.test_bridge.remote_import("uuid")
        remote_obj = remote_uuid.uuid4()

        self.assertTrue("<class 'uuid.UUID'>" in str(remote_obj._bridged_get_type()))
        self.assertTrue("'type'" in str(remote_obj._bridged_get_type()._bridged_get_type()))

    def test_remote_eval(self):
        self.assertEquals(3, TestBridge.test_bridge.remote_eval("1+2"))

    def test_remote_eval_bad_code(self):
        with self.assertRaises(bridge.BridgeException):
            TestBridge.test_bridge.remote_eval("1+x")

    def test_remote_eval_kwargs(self):
        self.assertEquals(3, TestBridge.test_bridge.remote_eval("x+y", x=1, y=2))

    def test_remote_eval_timeout(self):
        remote_time = TestBridge.test_bridge.remote_import("time")

        # check that it times out if not enough time allocated
        with self.assertRaises(Exception):
            TestBridge.test_bridge.remote_eval("sleep(2)", timeout_override=1, sleep=remote_time.sleep)

        # check that it works with enough time
        TestBridge.test_bridge.remote_eval("sleep(2)", timeout_override=3, sleep=remote_time.sleep)

    def test_operators(self):
        # check we can handle operator comparisons, addition, etc
        remote_datetime = TestBridge.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)

        self.assertTrue(td1 < td2)
        self.assertTrue(td2 >= td1)
        self.assertEquals(remote_datetime.timedelta(3), td1 + td2)
        self.assertEquals(td1, td2//2)  # we use floordiv here, truediv tested below

    def test_truediv(self):
        # check we cleanly fallback from truediv to div
        # timedelta in jython2.7 implements __div__ but not __truediv__
        remote_datetime = TestBridge.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)
        self.assertEquals(td1, td2/2)

    def test_len(self):
        # check we can handle len
        remote_collections = TestBridge.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        dq.append(1)
        dq.append(2)
        dq.append(3)
        self.assertEquals(3, len(dq))

    def test_bool(self):
        """ check we handle truthiness """
        remote_collections = TestBridge.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        self.assertFalse(bool(dq))

        dq.append(1)
        self.assertTrue(bool(dq))

        # check we handle custom truthiness
        class x:
            def __init__(self, y):
                self.y = y

            def __bool__(self):
                return self.y == 2
            __nonzero__ = __bool__

        f = x(3)
        self.assertFalse(TestBridge.test_bridge.remote_eval("bool(f)", f=f))
        t = x(2)
        self.assertTrue(TestBridge.test_bridge.remote_eval("bool(t)", t=t))

    def test_bytes(self):
        """ Test that we handle calling bytes() on a bridged object """
        remote_collections = TestBridge.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        dq.append(1)

        if sys.version_info[0] == 2:
            # bytes() == str() in py 2
            self.assertEquals(bytes(dq), "deque([1])")
        else:
            self.assertEquals(bytes(dq), b"\x01")


class TestBridgeHookImport(unittest.TestCase):
    """ Assumes there's a bridge server running at DEFAULT_SERVER_PORT."""

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        TestBridge.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG, hook_import=True)

    def test_hook_import_top_level(self):
        """ Test that we handle import x syntax """
        import test_hook_import_top_level
        remote_name = str(test_hook_import_top_level)
        self.assertTrue("BridgedModule" in remote_name and "test_hook_import_top_level" in remote_name)

    def test_hook_import_dotted(self):
        """ Test that we handle import x.y syntax """
        import test_hook_import_dotted.child
        remote_name = str(test_hook_import_dotted.child)
        self.assertTrue("BridgedModule" in remote_name and "test_hook_import_dotted.child" in remote_name)

    def test_hook_import_from_syntax(self):
        """ Test that we handle from x import y syntax """
        from test_hook_import_from import run_server
        remote_name = str(run_server)
        self.assertTrue("BridgedCallable" in remote_name and "run_server" in remote_name)

    def test_hook_import_nonexistent(self):
        """ Test that we handle a nonexistent import """
        with self.assertRaises(ImportError):
            import foobar

    def test_hook_import_as(self):
        """ Test that we don't break import x as y syntax """
        import test_hook_import_as as thia
        remote_name = str(thia)
        self.assertTrue("BridgedModule" in remote_name and "test_hook_import_as" in remote_name)

    def test_hook_import_force_import(self):
        """ Test that we actually import something that's not loaded"""
        remote_sys = TestBridge.test_bridge.remote_import("sys")
        remote_python_version = remote_sys.version_info[0]
        local_python_version = sys.version_info[0]

        if local_python_version == 2 and remote_python_version == 3:
            # import a module in 3 that's not in 2
            # make sure it's not already loaded remotely
            self.assertTrue("http" not in remote_sys.modules)
            import http
            remote_name = str(http)
            self.assertTrue("BridgedModule" in remote_name and "http" in remote_name)

        elif local_python_version == 3 and remote_python_version == 2:
            # import a module in 2 that's not in 3
            # make sure it's not already loaded remotely
            self.assertTrue("SimpleHTTPServer" not in remote_sys.modules)
            import SimpleHTTPServer
            remote_name = str(SimpleHTTPServer)
            self.assertTrue("BridgedModule" in remote_name and "SimpleHTTPServer" in remote_name)

        else:
            # same versions, can't think of anything useful to test load
            self.skipTest("Test irrelevant for matched versions")

    def test_local_import(self):
        """ Make sure a local import is resolved locally, not pulled in remotely """
        self.assertTrue("ast" not in sys.modules)
        import ast
        name = str(ast)
        self.assertTrue("BridgedModule" not in name and "ast" in name)
        
    def test_hook_import_nonmodule(self):
        """ Test we can import nonmodules like modules (e.g., java classes from jython). But mostly so we can test 
            reimporting
        """
        import test_hook_import_nonmodule
        remote_name = str(test_hook_import_nonmodule)
        self.assertTrue("BridgedCallable" in remote_name and "run_server" in remote_name)

class TestBridgeHookImportReimport(unittest.TestCase):
    """ 
    Test the case of a separate client importing the same module as a previous client.
    Because the modules are only imported once in the server, if the first client sets objects on the remote module
    (e.g., __spec__), the second client will get old/unknown handle.
    
    Assumes there's a bridge server running at DEFAULT_SERVER_PORT.
    """

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        old_importer_index = len(sys.path)-1
        TestBridge.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG, hook_import=True)

        # rearrange paths to make sure our importer gets called first
        # TODO once we get around to implementing cleaning up import hooks on client shutdown, this shouldn't be required
        new_importer = sys.path[-1]
        old_importer = sys.path[old_importer_index]
        sys.path[old_importer_index] = new_importer
        sys.path[-1] = old_importer

    def test_hook_import_nonmodule_again(self):
        """ If this fails with old/unknown handle, __spec__ has been set by the old client """
        # clear out our old import
        del sys.modules["test_hook_import_nonmodule"]
        
        import test_hook_import_nonmodule
        remote_name = str(test_hook_import_nonmodule)
        self.assertTrue("BridgedCallable" in remote_name and "run_server" in remote_name)

class TestBridgeZZZZZZZShutdown(unittest.TestCase):
    """ Assumes there's a bridge server running at DEFAULT_SERVER_PORT. Needs to run last, nothing will work after this"""

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        TestBridge.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG)

    def test_zzzzzz_shutdown(self):
        # test shutdown last
        result = TestBridge.test_bridge.remote_shutdown()
        self.assertTrue(result[bridge.SHUTDOWN])

        # give it a second to tear down
        time.sleep(1)

        # try to reconnect, should fail with connection refused
        with self.assertRaises(ConnectionRefusedError):
            fail_bridge = bridge.BridgeClient(
                connect_to_port=bridge.DEFAULT_SERVER_PORT, loglevel=logging.DEBUG)

            fail_bridge.remote_import("datetime")
