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
import functools
from collections import OrderedDict

from . import bridge
from . import test_module

if sys.version_info[0] == 2:
    from socket import (
        error as ConnectionRefusedError,
    )  # ConnectionRefusedError not defined in python2, this is next closest thing


def print_stats(func):
    @functools.wraps(func)
    def print_stats_wrapper(self, *args, **kwargs):
        start_stats = self.test_bridge.get_stats()
        func(self, *args, **kwargs)
        print(
            "\n{}:\n\t{}\n".format(
                func.__name__, self.test_bridge.get_stats() - start_stats
            )
        )

    return print_stats_wrapper


def sample_test_unindented_function():
    """Test function used to remoteify to make sure we can still send unindented stuff"""
    return 50


class TestBridge(unittest.TestCase):
    """Assumes there's a bridge server running at DEFAULT_SERVER_PORT"""

    @classmethod
    def setUpClass(cls):
        cls.pr = None
        try:
            # setup cprofile to profile (most) of the tests
            import cProfile

            cls.pr = cProfile.Profile()
            cls.pr.enable()
        except ImportError:
            pass  # expected for jython

        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        cls.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG, record_stats=True
        )
        cls.total_start_stats = cls.test_bridge.get_stats()

    @classmethod
    def tearDownClass(cls):
        total_stats = cls.test_bridge.get_stats()
        print(
            "\n{}:\n\t{}\n".format(
                "TestBridge Total", cls.test_bridge.get_stats() - cls.total_start_stats
            )
        )
        if cls.pr is not None:
            import pstats

            p = pstats.Stats(cls.pr)
            p.sort_stats("cumulative")
            p.print_stats()

    @print_stats
    def test_import(self):
        mod = self.test_bridge.remote_import("base64")
        self.assertTrue(mod is not None)

    @print_stats
    def test_call_no_args(self):

        mod = self.test_bridge.remote_import("uuid")

        result = mod.uuid4()

        self.assertTrue(result is not None)

    @print_stats
    def test_call_arg(self):
        # also tests call with bytestring arg in python3

        mod = self.test_bridge.remote_import("base64")

        test_str = str(uuid.uuid4())

        result_str = None
        if sys.version[0] == "3":
            result = mod.b64encode(test_str.encode("utf-8"))
            result_str = base64.b64decode(result).decode("utf-8")
        else:
            # python2 can't send a byte string, and if the other end is python3, b64encode won't work on a string.
            # instead we'll try creating a uuid from the string
            remote_uuid = self.test_bridge.remote_import("uuid")
            new_uuid = remote_uuid.UUID(test_str)
            result_str = str(new_uuid)

        self.assertEqual(test_str, result_str)

    @print_stats
    def test_call_multi_args(self):
        mod = self.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo", mod.IGNORECASE)

        self.assertTrue(remote_obj is not None)

        self.assertTrue(remote_obj.match("FOO") is not None)

    @print_stats
    def test_call_with_remote_obj(self):

        mod = self.test_bridge.remote_import("uuid")

        remote_obj = mod.uuid4()
        result = str(remote_obj)
        self.assertTrue(result is not None)
        self.assertTrue("-" in result and "4" in result)

    @print_stats
    def test_call_with_str(self):
        """also tests calling str() on remote obj"""

        mod = self.test_bridge.remote_import("uuid")

        test_uuid_str = "00010203-0405-0607-0809-0a0b0c0d0e0f"

        remote_uuid = mod.UUID(test_uuid_str)
        self.assertTrue(remote_uuid is not None)
        result = str(remote_uuid)
        self.assertEqual(test_uuid_str, result)

    # bool, int, list, tuple, dict, bytes, bridge object, callback, exception, none
    # set a function into the remote __main__/globals() to call
    # callback as key func in list.sort

    @print_stats
    def test_call_kwargs(self):
        self.skipTest("Not implemented yet")

    @print_stats
    def test_get(self):
        mod = self.test_bridge.remote_import("uuid")
        remote_doc = mod.__doc__
        self.assertTrue("RFC 4122" in remote_doc)

    @print_stats
    def test_set(self):
        test_string = "hello world"
        mod = self.test_bridge.remote_import("__main__")
        mod.test = test_string

        self.assertEqual(test_string, mod.test)

    @print_stats
    def test_get_non_existent(self):
        """Check that requesting a non-existent attribute over the bridge raises an attributeerror"""
        mod = self.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        with self.assertRaises(AttributeError):
            remote_obj.doesnt_exist

    @print_stats
    def test_get_callable(self):
        mod = self.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search
        self.assertTrue(isinstance(remote_callable, bridge.BridgedCallable))

    @print_stats
    def test_callable(self):
        mod = self.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.match

        self.assertTrue(remote_callable("fooa") is not None)

    @print_stats
    def test_serialize_deserialize_types(self):
        mod = self.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        # assemble a list of different types
        # Note: we include False now to detect failure to correctly unpack "False" strings into bools
        test_list = [
            1,
            0xFFFFFFFF,
            True,
            False,
            "string",
            "unicode_string🐉🔍",
            (1, 2, 3),
            [4, 5, 6],
            {7: 8, 9: 10},
            uuid.uuid4(),
            pow,
            1.5,
        ]

        # send the list in to create a remote list (which comes straight back)
        created_list = remote_list(test_list)

        # check it's the same
        self.assertEqual(test_list, created_list)

    @print_stats
    def test_serialize_deserialize_bytes(self):
        """byte strings across 2<->3 bridges will be forced to strings (because py2 treats bytes and strs as the same thing"""
        mod = self.test_bridge.remote_import("__main__")
        remote_list = mod.__builtins__.list

        test_list = [b"bytes"]

        # send the list in to create a remote list (which comes straight back)s
        created_list = remote_list(test_list)

        # check it's the same, either as a byte or normal string
        self.assertTrue(
            created_list[0] == test_list[0]
            or created_list[0] == test_list[0].decode("utf-8")
        )

    @print_stats
    def test_serialize_deserialize_bridge_object(self):
        # bridge objects TODO
        self.skipTest("Not implemented yet")

    @print_stats
    def test_none_result(self):
        mod = self.test_bridge.remote_import("re")

        remote_obj = mod.compile("foo")

        remote_callable = remote_obj.search

        self.assertTrue(remote_callable("abar") is None)

    @print_stats
    def test_exception(self):
        self.skipTest("Not implemented yet")

    @print_stats
    def test_callback(self):
        """Test we correctly handle calling back to here from across the bridge"""

        def sort_fn(val):
            return len(val)

        mod = self.test_bridge.remote_import("__main__")
        remote_sorted = mod.__builtins__.sorted

        test_list = ["aaa", "bb", "xxxx", "c"]
        sorted_list = remote_sorted(test_list, key=sort_fn)

        self.assertEqual(sorted(test_list, key=sort_fn), sorted_list)

    @print_stats
    def test_remote_iterable(self):
        """Test we can access values from a remote iterable"""
        mod = self.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)

        it_values = list(remote_it)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    @print_stats
    def test_remote_iterable_for(self):
        """Test we can access values from a remote iterable with a for loop"""
        mod = self.test_bridge.remote_import("__main__")
        remote_range = mod.__builtins__.range

        remote_it = remote_range(4, 10, 2)
        it_values = list()
        for value in remote_it:
            it_values.append(value)

        self.assertEqual(list(range(4, 10, 2)), it_values)

    @print_stats
    def test_float(self):
        """Test we can sent a float value"""
        remote_time = self.test_bridge.remote_import("time")
        remote_time.sleep(0.1)

    @print_stats
    def test_is_bridged_object(self):
        remote_uuid = self.test_bridge.remote_import("uuid")

        remote_obj = remote_uuid.uuid4()
        local_obj = uuid.uuid4()

        self.assertTrue(bridge._is_bridged_object(remote_obj))
        self.assertFalse(bridge._is_bridged_object(local_obj))

    @print_stats
    def test_bridged_isinstance(self):
        mod = self.test_bridge.remote_import("__main__")
        remote_float = mod.__builtins__.float
        remote_int = mod.__builtins__.int
        remote_uuid = self.test_bridge.remote_import("uuid")
        remote_class = remote_uuid.UUID
        remote_obj = remote_uuid.uuid4()
        local_class = uuid.UUID
        local_obj = uuid.uuid4()

        # local obj, local class
        self.assertTrue(bridge.bridged_isinstance(local_obj, local_class))
        self.assertFalse(bridge.bridged_isinstance(local_obj, float))

        # local obj, fully local tuple
        self.assertTrue(bridge.bridged_isinstance(local_obj, (float, local_class)))
        self.assertFalse(bridge.bridged_isinstance(local_obj, (float, int)))

        # local obj, mixed tuple
        self.assertTrue(
            bridge.bridged_isinstance(local_obj, (remote_class, float, local_class))
        )
        self.assertFalse(
            bridge.bridged_isinstance(local_obj, (remote_float, float, int))
        )

        # local obj, remote class
        self.assertFalse(bridge.bridged_isinstance(local_obj, remote_class))

        # local obj, fully remote tuple
        self.assertFalse(
            bridge.bridged_isinstance(local_obj, (remote_float, remote_class))
        )

        # remote obj, local class
        self.assertFalse(bridge.bridged_isinstance(remote_obj, local_class))

        # remote obj, fully local tuple
        self.assertFalse(bridge.bridged_isinstance(remote_obj, (float, local_class)))

        # remote obj, mixed tuple
        self.assertTrue(
            bridge.bridged_isinstance(remote_obj, (remote_class, float, local_class))
        )
        self.assertFalse(
            bridge.bridged_isinstance(remote_obj, (remote_float, float, int))
        )

        # remote obj, remote class
        self.assertTrue(bridge.bridged_isinstance(remote_obj, remote_class))
        self.assertFalse(bridge.bridged_isinstance(remote_obj, remote_float))

        # remote obj, fully remote tuple
        self.assertTrue(
            bridge.bridged_isinstance(remote_obj, (remote_float, remote_class))
        )
        self.assertFalse(
            bridge.bridged_isinstance(remote_obj, (remote_float, remote_int))
        )

    @print_stats
    def test_bridged_get_type(self):
        """Make sure we can get an object representing the type of a bridged object"""
        remote_uuid = self.test_bridge.remote_import("uuid")
        remote_obj = remote_uuid.uuid4()

        self.assertTrue("<class 'uuid.UUID'>" in str(remote_obj._bridged_get_type()))
        self.assertTrue(
            "'type'" in str(remote_obj._bridged_get_type()._bridged_get_type())
        )

    @print_stats
    def test_remote_eval(self):
        self.assertEqual(3, self.test_bridge.remote_eval("1+2"))

    @print_stats
    def test_remote_eval_bad_code(self):
        with self.assertRaises(bridge.BridgeException):
            self.test_bridge.remote_eval("1+x")

    @print_stats
    def test_remote_eval_kwargs(self):
        self.assertEqual(3, self.test_bridge.remote_eval("x+y", x=1, y=2))

    @print_stats
    def test_remote_eval_timeout(self):
        remote_time = self.test_bridge.remote_import("time")

        # check that it times out if not enough time allocated
        with self.assertRaises(bridge.BridgeTimeoutException):
            self.test_bridge.remote_eval(
                "sleep(2)", timeout_override=1, sleep=remote_time.sleep
            )

        # check that it works with enough time
        self.test_bridge.remote_eval(
            "sleep(2)", timeout_override=3, sleep=remote_time.sleep
        )

    @print_stats
    def test_operators(self):
        # check we can handle operator comparisons, addition, etc
        remote_datetime = self.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)

        self.assertTrue(td1 < td2)
        self.assertTrue(td2 >= td1)
        self.assertEqual(remote_datetime.timedelta(3), td1 + td2)
        self.assertEqual(td1, td2 // 2)  # we use floordiv here, truediv tested below

    @print_stats
    def test_truediv(self):
        # check we cleanly fallback from truediv to div
        # timedelta in jython2.7 implements __div__ but not __truediv__
        remote_datetime = self.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)
        self.assertEqual(td1, td2 / 2)

    @print_stats
    def test_len(self):
        # check we can handle len
        remote_collections = self.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        dq.append(1)
        dq.append(2)
        dq.append(3)
        self.assertEqual(3, len(dq))

    @print_stats
    def test_bool(self):
        """check we handle truthiness"""
        remote_collections = self.test_bridge.remote_import("collections")
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
        self.assertFalse(self.test_bridge.remote_eval("bool(f)", f=f))
        t = x(2)
        self.assertTrue(self.test_bridge.remote_eval("bool(t)", t=t))

    @print_stats
    def test_bytes(self):
        """Test that we handle calling bytes() on a bridged object"""
        remote_collections = self.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        dq.append(1)

        if sys.version_info[0] == 2:
            # bytes() == str() in py 2
            self.assertEqual(bytes(dq), "deque([1])")
        else:
            self.assertEqual(bytes(dq), b"\x01")

    @print_stats
    def test_hash(self):
        """Test that we handle calling hash()/inserting a bridged object into a dictionary"""
        remote_datetime = self.test_bridge.remote_import("datetime")
        td1 = remote_datetime.timedelta(1)
        td2 = remote_datetime.timedelta(2)

        h1 = hash(td1)
        h2 = hash(td2)
        self.assertNotEqual(h1, h2)

        # note that hashes of equivalent objects created locally will not necessarily have the same value, due to different implementations across python versions - so don't mix bridged/local objects in the same dictionary.

        d = dict()
        d[td1] = "a"
        d[td2] = "b"

        self.assertEqual(d[remote_datetime.timedelta(1)], "a")
        self.assertEqual(d[remote_datetime.timedelta(2)], "b")

    @print_stats
    def test_unhashable(self):
        """Test that we don't magically hash unhashable objects"""
        remote_collections = self.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        with self.assertRaises((TypeError, BridgeException)):
            hash(dq)

    @print_stats
    def test_slicing(self):
        """Test we can slice bridged objects"""
        mod = self.test_bridge.remote_import("__main__")
        remote_bytearray = mod.__builtins__.bytearray

        test = [10, 20, 30, 40, 50, 60]

        ba = remote_bytearray(test)

        # single start slice
        self.assertEqual(list(ba[2:]), test[2:])

        # single stop slice
        self.assertEqual(list(ba[:4]), test[:4])

        # single step slice
        self.assertEqual(list(ba[::-1]), test[::-1])

        # negative indices
        self.assertEqual(list(ba[:-1]), test[:-1])

        # all together now
        self.assertEqual(list(ba[1:4:-1]), test[1:4:-1])

        # make sure we can set with a slice as well
        ba[1:4] = [0]
        test[1:4] = [0]
        self.assertEqual(list(ba), test)

    @print_stats
    def test_remote_inheritance(self):
        """check that we can inherit from a remote type"""
        remote_collections = self.test_bridge.remote_import("collections")
        remote_deque = remote_collections.deque

        class new_deque(remote_deque):
            def __init__(self, test):
                remote_deque.__init__(self)
                self.test = test
                self.called = False

            def append(self, x):
                remote_deque.append(self, x)
                self.called = True

        nd = new_deque("test")
        self.assertEqual(nd.test, "test")

        nd.append(1)
        self.assertTrue(nd.called)
        self.assertEqual(nd.pop(), 1)

        self.assertTrue(
            not isinstance(nd.append, bridge.BridgedCallable),
            "Expected local implementation to stay local - is actually: "
            + str(type(nd.append)),
        )

    @print_stats
    def test_nonreturn(self):
        """Test we can call a bridged function as non-returning"""
        remote_time = self.test_bridge.remote_import("time")
        # would expect this to timeout - but instead should send off and keep going
        remote_time.sleep._bridge_call_nonreturn(10)

    @print_stats
    def test_nonreturn_doesnt_respond(self):
        """Test that a nonreturn call doesn't cause a response to show up"""
        remote_collections = self.test_bridge.remote_import("collections")
        dq = remote_collections.deque()
        # let any responses in flight trickle home
        time.sleep(1)
        # record the size of the response manager
        response_count = len(self.test_bridge.client.response_mgr.response_dict)
        # expect no response
        dq.append._bridge_call_nonreturn(1)
        # let any responses in flight trickle home
        time.sleep(1)
        # check that there aren't more responses
        self.assertTrue(
            response_count >= len(self.test_bridge.client.response_mgr.response_dict)
        )

    @print_stats
    def test_nonreturn_marker_remote(self):
        """Test that a callable marked as nonreturn doesn't return when called normally"""
        remote_main = self.test_bridge.remote_import("__main__")
        # would normally time out
        remote_main.nonreturn()

    @print_stats
    def test_nonreturn_marker_local(self):
        """Test that a callable marked as nonreturn doesn't return when called normally from the other side of the bridge"""

        class Callback:
            called = False

            @bridge.nonreturn
            def callback(self):
                self.called = True
                # cause a timeout
                time.sleep(10)

        c = Callback()

        # TODO known issue when server is 3.11 - this will get a timeout. Unknown why
        self.test_bridge.remote_eval("c.callback()", c=c, timeout_override=1)

        # pause to let the callback land
        time.sleep(1)
        self.assertTrue(c.called)

    @print_stats
    def test_remoteify_simple_function(self):
        """Test that we can remoteify a simple function"""

        def foobar():
            return True

        remote_foobar = self.test_bridge.remoteify(foobar)

        self.assertTrue(remote_foobar())

    @print_stats
    def test_remoteify_unindented(self):
        """Test that we can remoteify a function that isn't indented"""

        remote_unindented_function = self.test_bridge.remoteify(
            sample_test_unindented_function
        )

        self.assertEqual(50, remote_unindented_function())

    @print_stats
    def test_remoteify_same_names(self):
        """Test that we can remoteify some functions with the same name"""

        def foobar():
            return 10

        remote_foobar10 = self.test_bridge.remoteify(foobar)

        def foobar():
            return 20

        remote_foobar20 = self.test_bridge.remoteify(foobar)

        self.assertEqual(10, remote_foobar10())
        self.assertEqual(20, remote_foobar20())

    @print_stats
    def test_remoteify_function_with_args(self):
        """Test that we can remoteify a function that takes arguments"""

        def square(value):
            return value * value

        remote_square = self.test_bridge.remoteify(square)

        self.assertEqual(4, remote_square(2))

    @print_stats
    def test_remoteify_function_with_kwargs(self):
        """Test that we can remoteify a function and supply kwargs to the definition"""

        def flam():
            return defined_value

        remote_flam = self.test_bridge.remoteify(flam, defined_value=30)
        self.assertEqual(30, remote_flam())

    @print_stats
    def test_remoteify_function_with_imports(self):
        """Test that we can remoteify a function that uses imported modules"""

        def importer(val):
            from collections import deque

            d = deque()
            d.append(val)
            return d

        remote_importer = self.test_bridge.remoteify(importer)
        self.assertEqual(10, remote_importer(10).pop())

    @print_stats
    def test_remoteify_class(self):
        """Test that we can remoteify a class"""

        class CLZ:
            def __init__(self, val):
                self.val = val

        remote_clz = self.test_bridge.remoteify(CLZ)

        rc = remote_clz(20)
        self.assertEqual(20, rc.val)

    @print_stats
    def test_remoteify_class_with_inheritance(self):
        """Test that we can remoteify a class that inherits from a remote class"""
        remote_deque = (
            object  # lie to inspect locally that we're just inheriting from object
        )

        class new_deque(remote_deque):
            def __init__(self, test):
                remote_deque.__init__(self)
                self.test = test
                self.called = False

            def append(self, x):
                remote_deque.append(self, x)
                self.called = True

        remote_collections = self.test_bridge.remote_import("collections")
        remote_deque = remote_collections.deque

        remote_new_deque = self.test_bridge.remoteify(
            new_deque, remote_deque=remote_deque
        )

        nd = remote_new_deque("test")
        self.assertEqual(nd.test, "test")

        nd.append(1)
        self.assertTrue(nd.called)
        self.assertEqual(nd.pop(), 1)

        self.assertTrue(
            isinstance(nd.append, bridge.BridgedCallable),
            "Expected remoteified implementation to be remote - is actually: "
            + str(type(nd.append)),
        )

    @print_stats
    def test_remoteify_module(self):
        """Check we can remoteify a module"""
        remote_test_module = self.test_bridge.remoteify(test_module)
        remote_sys = self.test_bridge.remote_import("sys")
        self.assertEqual(remote_sys.version_info[0], remote_test_module.run())

    @print_stats
    def test_unicode_strings_only_when_required(self):
        """Moving away from old behaviour of forcing all strings across the bridge into python 2 to be unicode
        Instead, they'll now be forced to unicode, then attempt to drop back to plain strings."""
        remote_sys = self.test_bridge.remote_import("sys")
        remote_python_version = remote_sys.version_info[0]
        local_python_version = sys.version_info[0]

        # only relevant to test when python 2 is in the mix, either local or remote
        if local_python_version == 3 and remote_python_version == 3:
            self.skipTest("Test irrelevant for non python 2 setups")

        if remote_python_version == 2:
            # send the remote side strings that are plain and unicode and check what we get
            plain_string = str("string")
            unicode_string = "unicode_string🐉🔍"

            self.assertFalse(
                self.test_bridge.remote_eval(
                    "isinstance(plain_string, unicode)", plain_string=plain_string
                )
            )
            self.assertTrue(
                self.test_bridge.remote_eval(
                    "isinstance(unicode_string, unicode)", unicode_string=unicode_string
                )
            )
        elif local_python_version == 2:
            # get the remote side to send us strings that are plain and unicode and check what we get
            self.assertFalse(
                isinstance(self.test_bridge.remote_eval("'plain'"), unicode)
            )
            self.assertTrue(
                isinstance(
                    self.test_bridge.remote_eval(
                        "bytearray([240, 159, 144, 137]).decode('utf-8')"
                    ),
                    unicode,
                )
            )  # dragon emoji
        else:
            # same versions, can't think of anything useful to test load
            self.skipTest("Test irrelevant for matched versions")


class TestBridgeMutableContainers(unittest.TestCase):
    """Assumes there's a bridge server running at DEFAULT_SERVER_PORT"""

    @classmethod
    def setUpClass(cls):
        cls.pr = None
        try:
            # setup cprofile to profile (most) of the tests
            import cProfile

            cls.pr = cProfile.Profile()
            cls.pr.enable()
        except ImportError:
            pass  # expected for jython
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        cls.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG, record_stats=True
        )
        cls.total_start_stats = cls.test_bridge.get_stats()

    @classmethod
    def tearDownClass(cls):
        total_stats = cls.test_bridge.get_stats()
        print(
            "\n{}:\n\t{}\n".format(
                "TestBridgeMutableContainers Total",
                cls.test_bridge.get_stats() - cls.total_start_stats,
            )
        )
        if cls.pr is not None:
            import pstats

            p = pstats.Stats(cls.pr)
            p.sort_stats("cumulative")
            p.print_stats()

    @print_stats
    def test_mutable_list_set_index(self):
        # __setitem__
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list[0] = 2

        def remote_list_set_index(target_list, index, new_val):
            target_list[index] = new_val
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_set_index)(
            local_test_list, 0, 2
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_subclass(self):
        # check we still work for something that subclasses from list
        class List2(list):
            pass

        match_list = List2([3, 6, 7, 3])
        local_test_list = List2(match_list)
        match_list[0] = 2

        def remote_list_set_index(target_list, index, new_val):
            target_list[index] = new_val
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_set_index)(
            local_test_list, 0, 2
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_append(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list.append(1)

        def remote_list_append(target_list, new_val):
            target_list.append(new_val)
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_append)(
            local_test_list, 1
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_extend(self):
        match_list = [3, 6, 7, 3]
        extra_list = [1, 0, 9]
        local_test_list = list(match_list)
        match_list.extend(extra_list)

        def remote_list_extend(target_list, new_list):
            target_list.extend(new_list)
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_extend)(
            local_test_list, extra_list
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_clear(self):
        remote_sys = self.test_bridge.remote_import("sys")
        remote_python_version = remote_sys.version_info[0]
        local_python_version = sys.version_info[0]
        # not relevant for 2->2 setups - they don't have list.clear on either side
        if local_python_version == 2 and remote_python_version == 2:
            self.skipTest("Test irrelevant for non python 3 setups")

        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list = (
            []
        )  # manually clear it, so we can test on 2->3 setups where we don't have list.clear here

        def remote_list_clear(target_list):
            target_list.clear()
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_clear)(local_test_list)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_insert(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list.insert(2, 3)

        def remote_list_insert(target_list, index, new_val):
            target_list.insert(index, new_val)
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_insert)(
            local_test_list, 2, 3
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_del(self):
        # __delitem__
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        del match_list[2]

        def remote_list_del(target_list, index):
            del target_list[index]
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_del)(local_test_list, 2)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_remove(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list.remove(6)

        def remote_list_remove(target_list, val):
            target_list.remove(val)
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_remove)(
            local_test_list, 6
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_pop(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_val = match_list.pop()

        def remote_list_pop(target_list):
            val = target_list.pop()
            return target_list, val

        remote_result, remote_val = self.test_bridge.remoteify(remote_list_pop)(
            local_test_list
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")
        self.assertEqual(
            match_val, remote_val, "Local popped value didn't match remote popped value"
        )

    @print_stats
    def test_mutable_list_delslice(self):
        """Testing because py2 has a __delslice__ function that py3 doesn't"""
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        del match_list[2:3]

        def remote_list_delslice(target_list, slice_start, slice_end):
            del target_list[slice_start:slice_end]
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_delslice)(
            local_test_list, 2, 3
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_setslice(self):
        """Testing because py2 has a __setslice__ function that py3 doesn't"""
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list[2:4] = [4, 1]

        def remote_list_setslice(target_list, slice_start, slice_end, new_vals):
            target_list[slice_start:slice_end] = new_vals
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_setslice)(
            local_test_list, 2, 4, [4, 1]
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_getslice(self):
        """Testing because py2 has a __getslice__ function that py3 doesn't"""
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_slice = match_list[2:4]

        def remote_list_getslice(target_list, slice_start, slice_end):
            return target_list, target_list[slice_start:slice_end]

        remote_result, remote_slice = self.test_bridge.remoteify(remote_list_getslice)(
            local_test_list, 2, 4
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(match_slice, remote_slice, "Local slice didn't match target")

    @print_stats
    def test_mutable_list_reverse(self):
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list.reverse()

        def remote_list_reverse(target_list):
            target_list.reverse()
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_reverse)(local_test_list)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_sort(self):
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list.sort()

        def remote_list_sort(target_list):
            target_list.sort()
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_sort)(local_test_list)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_iadd(self):
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list += [4, 5]

        def remote_list_iadd(target_list, additional):
            target_list += additional
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_iadd)(
            local_test_list, [4, 5]
        )

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_imul(self):
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list *= 2

        def remote_list_imul(target_list, val):
            target_list *= val
            return target_list

        remote_result = self.test_bridge.remoteify(remote_list_imul)(local_test_list, 2)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_sorted(self):
        # Check that sorted() doesn't mutate
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        sorted_match_list = sorted(match_list)

        def remote_list_sorted(target_list):
            sorted_list = sorted(target_list)
            return target_list, sorted_list

        remote_list_result, remote_sorted_list = self.test_bridge.remoteify(
            remote_list_sorted
        )(local_test_list)

        self.assertEqual(
            match_list, remote_list_result, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            sorted_match_list, remote_sorted_list, "Local sort didn't match target"
        )

    @print_stats
    def test_mutable_list_in(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list.remove(6)

        def remote_list_in(target_list, val):
            init = val in target_list
            target_list.remove(val)
            post = val in target_list
            return target_list, init, post

        remote_result_list, init, post = self.test_bridge.remoteify(remote_list_in)(
            local_test_list, 6
        )

        self.assertEqual(
            match_list, remote_result_list, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")
        self.assertTrue(init, "Remote didn't find val as expected")
        self.assertFalse(post, "Remote found val unexpectedly after removal")

    @print_stats
    def test_mutable_list_get_after_mutate(self):
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)
        match_list[0] = 2

        def remote_list_set_index(target_list, index, new_val):
            target_list[index] = new_val
            return target_list, target_list[index]

        remote_result_list, remote_result_value = self.test_bridge.remoteify(
            remote_list_set_index
        )(local_test_list, 0, 2)

        self.assertEqual(
            match_list, remote_result_list, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            match_list[0],
            remote_result_value,
            "Updated value from remote didn't match target",
        )

    @print_stats
    def test_mutable_list_remote(self):
        # also tests __iter__
        match_list = [3, 6, 7, 3]
        local_test_list = list(match_list)

        def remote_list_create(target_list):
            new_list = []
            for x in target_list:
                new_list.append(x)

            return new_list

        remote_result = self.test_bridge.remoteify(remote_list_create)(local_test_list)

        self.assertEqual(match_list, remote_result, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_list_copy(self):
        remote_sys = self.test_bridge.remote_import("sys")
        remote_python_version = remote_sys.version_info[0]
        local_python_version = sys.version_info[0]

        # not relevant for 2->2 setups - they don't have list.copy on either side
        if local_python_version == 2 and remote_python_version == 2:
            self.skipTest("Test irrelevant for non python 3 setups")

        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)

        def remote_list_copy(target_list):
            copied_list = target_list.copy()
            return target_list, copied_list

        remote_list_result, remote_copied_list = self.test_bridge.remoteify(
            remote_list_copy
        )(local_test_list)

        self.assertEqual(
            match_list, remote_list_result, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            local_test_list, remote_copied_list, "Local list didn't match remote copy"
        )

    @print_stats
    def test_mutable_list_count(self):
        match_list = [3, 6, 7, 3, 5]
        pre_count = match_list.count(3)
        local_test_list = list(match_list)
        match_list[0] = 2
        post_count = match_list.count(3)

        def remote_list_count(target_list, val):
            pre_count = target_list.count(val)
            target_list[0] = 2
            post_count = target_list.count(val)
            return target_list, pre_count, post_count

        (
            remote_list_result,
            remote_pre_count,
            remote_post_count,
        ) = self.test_bridge.remoteify(remote_list_count)(local_test_list, 3)

        self.assertEqual(
            match_list, remote_list_result, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            pre_count,
            remote_pre_count,
            "Local pre-mod count didn't match remote pre-mod count",
        )
        self.assertEqual(
            post_count,
            remote_post_count,
            "Local pre-mod count didn't match remote pre-mod count",
        )

    @print_stats
    def test_mutable_list_len(self):
        match_list = [3, 6, 7, 3, 5]
        pre_len = len(match_list)
        local_test_list = list(match_list)
        match_list.pop()
        post_len = len(match_list)

        def remote_list_len(target_list):
            pre_len = len(target_list)
            target_list.pop()
            post_len = len(target_list)
            return target_list, pre_len, post_len

        (
            remote_list_result,
            remote_pre_len,
            remote_post_len,
        ) = self.test_bridge.remoteify(remote_list_len)(local_test_list)

        self.assertEqual(
            match_list, remote_list_result, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            pre_len, remote_pre_len, "Local pre-mod len didn't match remote pre-mod len"
        )
        self.assertEqual(
            post_len,
            remote_post_len,
            "Local pre-mod len didn't match remote pre-mod len",
        )

    @print_stats
    def test_mutable_list_unpacking(self):
        """Make sure we can unpack the mutable dict with * (e.g., if we're using it as args)"""
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)

        def remote_list_unpack(target_list):
            def capture(*args):
                return args

            return target_list, capture(*target_list)

        remote_list_result, remote_unpacked_tuple = self.test_bridge.remoteify(
            remote_list_unpack
        )(local_test_list)

        self.assertEqual(
            match_list, remote_list_result, "Remote list didn't match target"
        )
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

        self.assertEqual(
            local_test_list,
            list(remote_unpacked_tuple),
            "Local list didn't match remote unpack",
        )

    @print_stats
    def test_mutable_list_subcontainer(self):
        """Check we can modify a list inside a list"""
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list[2] = 20

        def remote_list_subcontainer(outer_list, list_idx, target_idx, value):
            target_list = outer_list[list_idx]
            target_list[target_idx] = value

            return target_list

        remote_list = self.test_bridge.remoteify(remote_list_subcontainer)(
            [local_test_list], 0, 2, 20
        )

        self.assertEqual(match_list, remote_list, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_dict_set_key(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict["b"] = 2

        def remote_dict_set_key(target_dict, key, new_val):
            target_dict[key] = new_val
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_set_key)(
            local_test_dict, "b", 2
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_get_after_mutate(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict["b"] = 2

        def remote_dict_set_key(target_dict, key, new_val):
            target_dict[key] = new_val
            return target_dict, target_dict[key]

        remote_result_dict, remote_result_value = self.test_bridge.remoteify(
            remote_dict_set_key
        )(local_test_dict, "b", 2)

        self.assertEqual(
            match_dict, remote_result_dict, "Remote list didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local list didn't match target")

        self.assertEqual(
            match_dict["b"],
            remote_result_value,
            "Updated value from remote didn't match target",
        )

    @print_stats
    def test_mutable_dict_subclass(self):
        # check we still work for something that subclasses from dict
        class Dict2(dict):
            pass

        match_dict = Dict2({"a": 1, "c": 4, "b": 10, "x": 20})
        local_test_dict = match_dict.copy()
        match_dict["b"] = 2

        def remote_dict_set_key(target_dict, key, new_val):
            target_dict[key] = new_val
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_set_key)(
            local_test_dict, "b", 2
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_setdefault(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict.setdefault("b", 2)  # a change that won't happen
        match_dict.setdefault("d", 2)  # a change that will happen

        def remote_dict_setdefault(target_dict):
            # we do two calls here - one that won't happen, and one that will happen. Atm, both are mutating, but just covering a potential future path if we decide to check if setdefault will cause  a mutation
            target_dict.setdefault("b", 2)  # a change that won't happen
            target_dict.setdefault("d", 2)  # a change that will happen
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_setdefault)(
            local_test_dict
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_pop(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        local_result = match_dict.pop("b")

        def remote_dict_pop(target_dict, key):
            result = target_dict.pop(key)
            return target_dict, result

        remote_dict, remote_result = self.test_bridge.remoteify(remote_dict_pop)(
            local_test_dict, "b"
        )

        self.assertEqual(match_dict, remote_dict, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            local_result, remote_result, "Local result didn't match target"
        )

    @print_stats
    def test_mutable_dict_popitem(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        local_result = match_dict.popitem()

        def remote_dict_popitem(target_dict):
            result = target_dict.popitem()
            return target_dict, result

        remote_dict, remote_result = self.test_bridge.remoteify(remote_dict_popitem)(
            local_test_dict
        )

        self.assertEqual(match_dict, remote_dict, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            local_result, remote_result, "Local result didn't match target"
        )

    @print_stats
    def test_mutable_dict_update(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        update_vals = {"b": 3, "d": 4}
        match_dict.update(update_vals)

        def remote_dict_update(target_dict, new_vals):
            target_dict.update(new_vals)
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_update)(
            local_test_dict, update_vals
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_ior(self):
        remote_sys = self.test_bridge.remote_import("sys")
        remote_python_version = remote_sys.version_info[0]
        local_python_version = sys.version_info[0]
        # not relevant for py2 dicts - dict |= dict isn't valid
        # but we still want to test with a py3 ior against a bridged py2 dict
        if remote_python_version == 2:
            self.skipTest("Python2 doesn't support dict |= dict")

        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        update_vals = {"b": 3, "d": 4}
        match_dict.update(update_vals)  # same affect as ior

        def remote_dict_ior(target_dict, new_vals):
            # only valid in remote py3, against a py3 or py2 list
            target_dict |= new_vals
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_ior)(
            local_test_dict, update_vals
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_clear(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict.clear()

        def remote_dict_clear(target_dict):
            target_dict.clear()
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_clear)(local_test_dict)

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_del(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        del match_dict["c"]

        def remote_dict_del(target_dict, key):
            del target_dict[key]
            return target_dict

        remote_result = self.test_bridge.remoteify(remote_dict_del)(
            local_test_dict, "c"
        )

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_in(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        del match_dict["c"]

        def remote_dict_in(target_dict, key):
            init = key in target_dict
            del target_dict[key]
            post = key in target_dict
            return target_dict, init, post

        remote_result_list, init, post = self.test_bridge.remoteify(remote_dict_in)(
            local_test_dict, "c"
        )

        self.assertEqual(
            match_dict, remote_result_list, "Remote dict didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")
        self.assertTrue(init, "Remote didn't find key as expected")
        self.assertFalse(post, "Remote found key unexpectedly after removal")

    @print_stats
    def test_mutable_dict_has_key(self):
        # test we map the deprecated py2 has_key to __contains__
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        del match_dict["c"]

        def remote_dict_has_key(target_dict, key):
            init = target_dict.has_key(key)
            del target_dict[key]
            post = target_dict.has_key(key)
            return target_dict, init, post

        remote_result_list, init, post = self.test_bridge.remoteify(
            remote_dict_has_key
        )(local_test_dict, "c")

        self.assertEqual(
            match_dict, remote_result_list, "Remote dict didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")
        self.assertTrue(init, "Remote didn't find key as expected")
        self.assertFalse(post, "Remote found key unexpectedly after removal")

    @print_stats
    def test_mutable_dict_len(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        pre_len = len(match_dict)
        match_dict.pop("b")
        post_len = len(match_dict)

        def remote_dict_len(target_dict):
            pre_len = len(target_dict)
            target_dict.pop("b")
            post_len = len(target_dict)
            return target_dict, pre_len, post_len

        (
            remote_dict_result,
            remote_pre_len,
            remote_post_len,
        ) = self.test_bridge.remoteify(remote_dict_len)(local_test_dict)

        self.assertEqual(
            match_dict, remote_dict_result, "Remote dict didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            pre_len, remote_pre_len, "Local pre-mod len didn't match remote pre-mod len"
        )
        self.assertEqual(
            post_len,
            remote_post_len,
            "Local pre-mod len didn't match remote pre-mod len",
        )

    @print_stats
    def test_mutable_dict_remote(self):
        # also tests items
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()

        def remote_dict_create(target_dict):
            new_dict = {k: v for k, v in target_dict.items()}

            return new_dict

        remote_result = self.test_bridge.remoteify(remote_dict_create)(local_test_dict)

        self.assertEqual(match_dict, remote_result, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_dict_str_repr(self):
        # make sure str and repr display what we expect.

        # We use ordereddict to make sure we get our str output the same on both sides
        match_dict = OrderedDict()
        match_dict[
            str("a")
        ] = 1  # Note: we explicitly use str() here to avoid edge case with py2 where the unicode strings get forced to ascii by the bridge (intended behaviour)
        match_dict[str("c")] = 4
        match_dict[str("b")] = 10
        match_dict[str("x")] = 20

        local_test_dict = match_dict.copy()

        def remote_dict_create(target_dict):
            from collections import OrderedDict

            new_dict = OrderedDict()
            for k, v in target_dict.items():
                new_dict[k] = v
            return new_dict

        remote_result = self.test_bridge.remoteify(remote_dict_create)(local_test_dict)
        # str should be the same as the matching dict
        self.assertEqual(str(match_dict), str(remote_result))

        # repr should look like <BridgedDictProxy(<_bridged_dict('{'a': 1, 'c': 4, 'b': 10, 'x': 20}', type=dict, handle=d1a00ab2-422b-4c6a-ba0d-681cb2d9f675)>, local_cache={'a': 1, 'x': 20, 'c': 4, 'b': 10})> before any modification happens
        remote_rep = repr(remote_result)
        self.assertIn("BridgedDictProxy", remote_rep)
        self.assertIn("'" + str(match_dict) + "'", remote_rep)
        self.assertIn("local_cache=" + str(match_dict), remote_rep)

        # make a modification to drop the local cache
        remote_result.pop("a")
        match_dict.pop("a")
        self.assertEqual(str(match_dict), str(remote_result))

        remote_rep2 = repr(remote_result)
        self.assertIn("'" + str(match_dict) + "'", remote_rep2)
        self.assertIn("local_cache=None", remote_rep2)

    @print_stats
    def test_mutable_dict_copy(self):
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()

        def remote_dict_copy(target_dict):
            copied_dict = target_dict.copy()
            return target_dict, copied_dict

        remote_dict_result, remote_copied_dict = self.test_bridge.remoteify(
            remote_dict_copy
        )(local_test_dict)

        self.assertEqual(
            match_dict, remote_dict_result, "Remote dict didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            local_test_dict, remote_copied_dict, "Local dict didn't match remote copy"
        )

    @print_stats
    def test_mutable_dict_unpacking(self):
        """Make sure we can unpack the mutable dict with ** (e.g., if we're using it as kwargs)"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()

        def remote_dict_unpack(target_dict):
            def capture(**kwargs):
                return kwargs

            return target_dict, capture(**target_dict)

        remote_dict_result, remote_unpacked_dict = self.test_bridge.remoteify(
            remote_dict_unpack
        )(local_test_dict)

        self.assertEqual(
            match_dict, remote_dict_result, "Remote dict didn't match target"
        )
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            local_test_dict,
            remote_unpacked_dict,
            "Local dict didn't match remote unpack",
        )

    @print_stats
    def test_mutable_dict_viewitems(self):
        """check that we map the deprecated py2 viewitems to items"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()

        def remote_dict_viewitems(target_dict, key):
            new_dict = {}
            for k, v in target_dict.viewitems():
                new_dict[k] = v
            return target_dict, new_dict

        remote_dict, remote_result = self.test_bridge.remoteify(remote_dict_viewitems)(
            local_test_dict, "b"
        )

        self.assertEqual(match_dict, remote_dict, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(
            match_dict, remote_result, "Local dict didn't match viewed target"
        )

    @print_stats
    def test_mutable_dict_subcontainer(self):
        """Check we can modify a dict inside a dict"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict["b"] = 20

        def remote_dict_subcontainer(outer_dict, dict_key, target_key, value):
            target_dict = outer_dict[dict_key]
            target_dict[target_key] = value

            return target_dict

        remote_dict = self.test_bridge.remoteify(remote_dict_subcontainer)(
            {"dict": local_test_dict}, "dict", "b", 20
        )

        self.assertEqual(match_dict, remote_dict, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

    @print_stats
    def test_mutable_remote_call_kwargs(self):
        """Make sure that we can mutate containers sent as kwargs in a remote call"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict["a"] = 20
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list[2] = 20

        def remote_mutate_kwargs(d=None, l=None):
            d["a"] = 20
            l[2] = 20

            return d, l

        remote_dict, remote_list = self.test_bridge.remoteify(remote_mutate_kwargs)(
            d=local_test_dict, l=local_test_list
        )

        self.assertEqual(match_dict, remote_dict, "Remote dict didn't match target")
        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(match_list, remote_list, "Remote list didn't match target")
        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_remote_eval_kwargs(self):
        """Make sure that we can mutate containers sent as kwargs in a remote eval"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict.pop("a")
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list.pop()

        self.test_bridge.remote_eval("d.pop('a')", d=local_test_dict)
        self.test_bridge.remote_eval("l.pop()", l=local_test_list)

        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(match_list, local_test_list, "Local list didn't match target")

    @print_stats
    def test_mutable_remote_exec_kwargs(self):
        """Make sure that we can mutate containers sent as kwargs in a remote exec"""
        match_dict = {"a": 1, "c": 4, "b": 10, "x": 20}
        local_test_dict = match_dict.copy()
        match_dict["a"] = 20
        match_list = [3, 6, 7, 3, 5]
        local_test_list = list(match_list)
        match_list[2] = 20

        self.test_bridge.remote_exec(
            "d['a'] = 20; l[2] = 20", d=local_test_dict, l=local_test_list
        )

        self.assertEqual(match_dict, local_test_dict, "Local dict didn't match target")

        self.assertEqual(match_list, local_test_list, "Local list didn't match target")


class TestBridgeHookImport(unittest.TestCase):
    """Assumes there's a bridge server running at DEFAULT_SERVER_PORT."""

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        cls.test_bridge = bridge.BridgeClient(
            connect_to_port=port,
            loglevel=logging.DEBUG,
            hook_import=True,
            record_stats=True,
        )

        cls.total_start_stats = cls.test_bridge.get_stats()

    @classmethod
    def tearDownClass(cls):
        total_stats = cls.test_bridge.get_stats()
        print(
            "\n{}:\n\t{}\n".format(
                "TestBridgeHookImport Total",
                cls.test_bridge.get_stats() - cls.total_start_stats,
            )
        )

    @print_stats
    def test_hook_import_top_level(self):
        """Test that we handle import x syntax"""
        import test_hook_import_top_level

        remote_name = str(test_hook_import_top_level)
        self.assertTrue(
            "BridgedModule" in remote_name
            and "test_hook_import_top_level" in remote_name
        )

    @print_stats
    def test_hook_import_dotted(self):
        """Test that we handle import x.y syntax"""
        import test_hook_import_dotted.child

        remote_name = str(test_hook_import_dotted.child)
        self.assertTrue(
            "BridgedModule" in remote_name
            and "test_hook_import_dotted.child" in remote_name
        )

    @print_stats
    def test_hook_import_from_syntax(self):
        """Test that we handle from x import y syntax"""
        from test_hook_import_from import run_server

        remote_name = str(run_server)
        self.assertTrue(
            "BridgedCallable" in remote_name and "run_server" in remote_name
        )

    @print_stats
    def test_hook_import_nonexistent(self):
        """Test that we handle a nonexistent import"""
        with self.assertRaises(ImportError):
            import foobar

    @print_stats
    def test_hook_import_as(self):
        """Test that we don't break import x as y syntax"""
        import test_hook_import_as as thia

        remote_name = str(thia)
        self.assertTrue(
            "BridgedModule" in remote_name and "test_hook_import_as" in remote_name
        )

    @print_stats
    def test_hook_import_force_import(self):
        """Test that we actually import something that's not loaded"""
        remote_sys = self.test_bridge.remote_import("sys")
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
            self.assertTrue(
                "BridgedModule" in remote_name and "SimpleHTTPServer" in remote_name
            )

        else:
            # same versions, can't think of anything useful to test load
            self.skipTest("Test irrelevant for matched versions")

    @print_stats
    def test_local_import(self):
        """Make sure a local import is resolved locally, not pulled in remotely"""
        self.assertTrue(
            "tarfile" not in sys.modules
        )  # check to make sure our target hasn't already been imported
        import tarfile

        name = str(tarfile)
        self.assertTrue("BridgedModule" not in name and "tarfile" in name)

    @print_stats
    def test_hook_import_nonmodule(self):
        """Test we can import nonmodules like modules (e.g., java classes from jython). But mostly so we can test
        reimporting
        """
        import test_hook_import_nonmodule

        remote_name = str(test_hook_import_nonmodule)
        self.assertTrue(
            "BridgedCallable" in remote_name and "run_server" in remote_name
        )


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
        old_importer_index = len(sys.path) - 1
        cls.test_bridge = bridge.BridgeClient(
            connect_to_port=port,
            loglevel=logging.DEBUG,
            hook_import=True,
            record_stats=True,
        )

        cls.total_start_stats = cls.test_bridge.get_stats()

        # rearrange paths to make sure our importer gets called first
        # TODO once we get around to implementing cleaning up import hooks on client shutdown, this shouldn't be required
        new_importer = sys.path[-1]
        old_importer = sys.path[old_importer_index]
        sys.path[old_importer_index] = new_importer
        sys.path[-1] = old_importer

    @classmethod
    def tearDownClass(cls):
        total_stats = cls.test_bridge.get_stats()
        print(
            "\n{}:\n\t{}\n".format(
                "TestBridgeHookImportReimport Total",
                cls.test_bridge.get_stats() - cls.total_start_stats,
            )
        )

    @print_stats
    def test_hook_import_nonmodule_again(self):
        """If this fails with old/unknown handle, __spec__ has been set by the old client"""
        # clear out our old import
        del sys.modules["test_hook_import_nonmodule"]

        import test_hook_import_nonmodule

        remote_name = str(test_hook_import_nonmodule)
        self.assertTrue(
            "BridgedCallable" in remote_name and "run_server" in remote_name
        )


class TestBridgeZZZZZZZShutdown(unittest.TestCase):
    """Assumes there's a bridge server running at DEFAULT_SERVER_PORT. Needs to run last, nothing will work after this"""

    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
        cls.test_bridge = bridge.BridgeClient(
            connect_to_port=port, loglevel=logging.DEBUG, record_stats=True
        )

        cls.total_start_stats = cls.test_bridge.get_stats()

    @classmethod
    def tearDownClass(cls):
        total_stats = cls.test_bridge.get_stats()
        print(
            "\n{}:\n\t{}\n".format(
                "TestBridgeZZZZZZZShutdown Total",
                cls.test_bridge.get_stats() - cls.total_start_stats,
            )
        )

    @print_stats
    def test_zzzzzz_shutdown(self):
        # test shutdown last
        result = self.test_bridge.remote_shutdown()
        self.assertTrue(result[bridge.SHUTDOWN])

        # give it a second to tear down
        time.sleep(1)

        # try to reconnect, should fail with connection refused
        with self.assertRaises(ConnectionRefusedError):
            fail_bridge = bridge.BridgeClient(
                connect_to_port=bridge.DEFAULT_SERVER_PORT, loglevel=logging.DEBUG
            )

            fail_bridge.remote_import("datetime")
