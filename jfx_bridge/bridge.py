""" Handles converting data back and forward between 2 and 3 """

from __future__ import unicode_literals  # string literals are all unicode

try:
    import SocketServer as socketserver  # py2
except Exception:
    import socketserver  # py3

import logging
import json
import base64
import uuid
import threading
import importlib
import socket
import struct
import sys
import time
import traceback
import weakref
import functools
import operator
import warnings
import inspect
import random
import textwrap
import types
import collections

import cProfile
import pstats

__version__ = "0.0.0"  # automatically patched by setup.py when packaging

# record the python version we're running locally, for when we need to do 2/3 stuff
PYTHON_VERSION = sys.version_info[0]

# from six.py's strategy
INTEGER_TYPES = None
try:
    INTEGER_TYPES = (int, long)
except NameError:  # py3 has no long
    INTEGER_TYPES = (int,)

STRING_TYPES = None
try:
    STRING_TYPES = (str, unicode)
except NameError:  # py3 has no unicode
    STRING_TYPES = (str,)


# need to pick up java.lang.Throwable as an exception type if we're in a jython context
EXCEPTION_TYPES = None
try:
    import java

    EXCEPTION_TYPES = (Exception, java.lang.Throwable)
except ImportError:
    # Nope, just normal python here
    EXCEPTION_TYPES = (Exception,)

ENUM_TYPE = ()
try:
    from enum import Enum

    ENUM_TYPE = (Enum,)
except ImportError:  # py2 has no enum
    pass

if PYTHON_VERSION == 2:
    from socket import (
        error as ConnectionError,
    )  # ConnectionError not defined in python2, this is next closest thing
    from socket import error as ConnectionResetError  # as above


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # prevent server threads hanging around and stopping python from closing
    daemon_threads = True


DEFAULT_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 27238  # 0x6a66 = "jf"

VERSION = "v"
MAX_VERSION = "max_v"
MIN_VERSION = "min_v"
COMMS_VERSION_6 = 6
TYPE = "type"
VALUE = "value"
KEY = "key"
TUPLE = "tuple"
LIST = "list"
DICT = "dict"
INT = "int"
FLOAT = "float"
BOOL = "bool"
STR = "str"
BYTES = "bytes"
NONE = "none"
PARTIAL = "partial"
SLICE = "slice"
NOTIMPLEMENTED = "notimp"
BRIDGED = "bridged"
EXCEPTION = "exception"
OBJ = "obj"
CALLABLE_OBJ = "callable_obj"
BASES = "bases"
REPR = "repr"

MESSAGE = "message"
CMD = "cmd"
ID = "ID"
ARGS = "args"
GET = "get"
GET_ALL = "get_all"
CREATE_TYPE = "create_type"
SET = "set"
ISINSTANCE = "isinstance"
CALL = "call"
IMPORT = "import"
DEL = "del"
EVAL = "eval"
EXEC = "exec"
EXPR = "expr"
RESULT = "result"
ERROR = "error"
SHUTDOWN = "shutdown"
RESPOND = "respond"

HANDLE = "handle"
NAME = "name"
ATTRS = "attrs"

KWARGS = "kwargs"

BRIDGE_PREFIX = "_bridge"

# Comms v6 passes handles for dicts and lists to allow them to be remotely mutable - one day, I'll support backwards compatibility
MIN_SUPPORTED_COMMS_VERSION = COMMS_VERSION_6
MAX_SUPPORTED_COMMS_VERSION = COMMS_VERSION_6

DEFAULT_RESPONSE_TIMEOUT = 2  # seconds

GLOBAL_BRIDGE_SHUTDOWN = False

# BridgedObjects have a little trouble with class methods (e.g., where the method of accessing is not instance.doThing(),  but more like
# type(instance).doThing(instance) - such as __lt__, len(), str().
# To handle this, we define a list of class methods that we want to expose - this is a little gross, I'd like to dynamically do this based on the methods in the
# bridged object's type, but need to come up with a blacklist of things like __class__, __new__, etc which will interfere with the local objects first
BRIDGED_CLASS_METHODS = ["__str__", "__len__", "__iter__", "__hash__"]
# extract methods from operator, so I don't have to type out all the different options
for operator_name in dir(operator):
    # only do the methods that start and end with __, and exclude __new__
    if (
        operator_name.startswith("__")
        and operator_name.endswith("__")
        and operator_name != "__new__"
        and "builtin_function_or_method" in str(type(getattr(operator, operator_name)))
    ):
        BRIDGED_CLASS_METHODS.append(operator_name)


class BridgeException(Exception):
    """An exception happened on the other side of the bridge and has been proxied back here
    The bridge is fine, but the remote code you ran might have had an issue.
    """

    pass


class BridgeOperationException(Exception):
    """Some issue happened with the operation of the bridge itself. The bridge may not be in a good state"""

    pass


class BridgeClosedException(Exception):
    """The bridge has closed"""

    pass


class BridgeTimeoutException(Exception):
    """A command we tried to run across the bridge took too long. You might need to increase the response timeout, check the command isn't
    causing a deadlock, or make sure the network connection to the other end of the bridge is okay.
    """

    pass


class OneWayDict(dict):
    """Simple wrapper around a dict that indicates that we don't want to remotely query or mutate it across the bridge. This gives better performance - don't need to ship a handle across in the first place, and don't have the remote side telling us when it releases it.

    Represented on the remote side by a normal dict populated with the same values as when it was first serialized.

    Note: can still be mutated locally, but changes after serialization won't be reflected on the remote side.
    """

    pass


class OneWayList(list):
    """As per OneWayDict, but for lists. Not used internally at the moment, may not be needed."""

    pass


def stats_hit(func):
    """Decorate a function to record how many times it gets hit. Assumes the function is in a class with a stats attribute (can be set to None to
    disable stats recording
    """

    @functools.wraps(func)
    def stats_hit_wrapper(self, *args, **kwargs):
        if self.stats is not None:
            self.stats.add_hit(func.__name__)
        return func(self, *args, **kwargs)

    return stats_hit_wrapper


def stats_time(func):
    """Decorate a function to record how long it takes to execute. Assumes the function is in a class with a stats attribute (can be set to None to
    disable stats recording
    """

    @functools.wraps(func)
    def stats_time_wrapper(self, *args, **kwargs):
        start_time = time.time()
        return_val = func(self, *args, **kwargs)
        total_time = time.time() - start_time

        if self.stats is not None:
            self.stats.add_time(func.__name__, total_time)

        return return_val

    return stats_time_wrapper


class Stats:
    """Class to record the number of hits of particular points (e.g., function calls) and
    times (e.g., execution times) for gathering statistics.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = dict()  # name -> hit count
        self.times = dict()  # name -> (hit count, cumulative_time)

    def add_hit(self, hit_name):
        with self.lock:
            hit_count = self.hits.get(hit_name, 0)
            self.hits[hit_name] = hit_count + 1

    def add_time(self, time_name, time):
        with self.lock:
            hit_count, cumulative_time = self.times.get(time_name, (0, 0))
            self.times[time_name] = (hit_count + 1, cumulative_time + time)

    def total_hits(self):
        total = 0
        with self.lock:
            for value in self.hits.values():
                total += value

        return total

    def total_time(self):
        total_time_hits = 0
        total_time = 0
        with self.lock:
            for hits, cumulative_time in self.times.values():
                total_time_hits += hits
                total_time += cumulative_time

        return (total_time_hits, total_time)

    def __str__(self):
        return "Stats(total_hits={},hits={},total_time={},times={})".format(
            self.total_hits(), self.hits, self.total_time(), self.times
        )

    def copy(self):
        """Take a copy of the stats at the current time"""
        copy_stats = Stats()
        with self.lock:
            copy_stats.hits = self.hits.copy()
            copy_stats.times = self.times.copy()

        return copy_stats

    def __sub__(self, other):
        if not isinstance(other, Stats):
            raise Exception("Can't subtract non-Stats object from a Stats object")

        # take a copy of this stats, then subtract the other from the copy
        new_stats = self.copy()

        # subtract the value of each key in other hits from the corresponding key in new_stats
        # if new_stats doesn't have the key, treat it as 0
        # nuke any values which end up as 0
        for key, value in other.hits.items():
            new_stats.hits[key] = new_stats.hits.get(key, 0) - value
            if new_stats.hits[key] == 0:
                del new_stats.hits[key]

        # as above, but for times
        for key, value in other.times.items():
            hit_count, cumulative_time = new_stats.times.get(key, (0, 0))
            new_stats.times[key] = (hit_count - value[0], cumulative_time - value[1])
            if new_stats.times[key][0] == 0:
                del new_stats.times[key]

        return new_stats


SIZE_FORMAT = "!I"


def write_size_and_data_to_socket(sock, data):
    """Utility function to pack the size in front of data and send it off

    Note: not thread safe - sock.send can return before all the data is sent, python can swap active threads, and another thread can start sending its data halfway through
    the first one's. Call from BridgeConn.send_data()
    """

    # pack the size as network-endian
    data_size = len(data)
    size_bytes = struct.pack(SIZE_FORMAT, len(data))
    package = size_bytes + data
    total_size = len(size_bytes) + data_size

    sent = 0
    # noted errors sending large blobs of data with sendall, so we'll send as much as send() allows and keep trying
    while sent < total_size:
        # send it all off
        bytes_sent = sock.send(package[sent:])
        sent = sent + bytes_sent


def read_exactly(sock, num_bytes):
    """Utility function to keep reading from the socket until we get the desired number of bytes"""
    data = b""
    while num_bytes > 0:
        new_data = sock.recv(num_bytes)
        if len(new_data) == 0:
            # most likely reason for no data here is the socket being closed on the remote end
            raise BridgeClosedException()
        num_bytes = num_bytes - len(new_data)
        data += new_data

    return data


def read_size_and_data_from_socket(sock):
    """Utility function to read the size of a data block, followed by all of that data"""

    size_bytes = read_exactly(sock, struct.calcsize(SIZE_FORMAT))
    size = struct.unpack(SIZE_FORMAT, size_bytes)[0]

    data = read_exactly(sock, size)
    data = data.strip()

    return data


def can_handle_version(message_dict):
    """Utility function for checking we know about this version"""
    return (message_dict[VERSION] <= MAX_SUPPORTED_COMMS_VERSION) and (
        message_dict[VERSION] >= MIN_SUPPORTED_COMMS_VERSION
    )


class BridgeCommandHandlerThread(threading.Thread):
    """Thread that checks for commands to handle and serves them"""

    bridge_conn = None
    threadpool = None

    def __init__(self, threadpool):
        super(BridgeCommandHandlerThread, self).__init__()

        self.bridge_conn = threadpool.bridge_conn
        # make sure this thread doesn't keep the threadpool alive
        self.threadpool = weakref.proxy(threadpool)

        # don't let the command handlers keep us alive
        self.daemon = True

    def run(self):
        try:
            cmd = self.threadpool.get_command()  # block, waiting for first command
            while cmd is not None:  # get_command returns none if we should shut down
                # handle a command and write back the response
                # TODO make this return an error tied to the cmd_id, so it goes in the response mgr
                result = None

                # see if the command wants a response
                want_response = cmd.get(RESPOND, True)

                try:
                    result = self.bridge_conn.handle_command(
                        cmd, want_response=want_response
                    )
                except EXCEPTION_TYPES as e:
                    self.bridge_conn.logger.error(
                        "Unexpected exception for {}: {}\n{}".format(
                            cmd, e, traceback.format_exc()
                        )
                    )
                    # pack a minimal error, so the other end doesn't have to wait for a timeout
                    result = json.dumps(
                        {
                            VERSION: COMMS_VERSION_6,
                            TYPE: ERROR,
                            ID: cmd[ID],
                        }
                    ).encode("utf-8")

                # only reply if the command wants a response
                if want_response:
                    try:
                        self.bridge_conn.send_data(result)
                    except socket.error:
                        # Other end has closed the socket before we can respond. That's fine, just ask me to do something then ignore me. Jerk. Don't bother staying around, they're probably dead
                        break

                cmd = self.threadpool.get_command()  # block, waiting for next command
        except ReferenceError:
            # expected, means the connection has been closed and the threadpool cleaned up
            pass


class BridgeCommandHandlerThreadPool(object):
    """Takes commands and handles spinning up threads to run them. Will keep the threads that are started and reuse them before creating new ones"""

    bridge_conn = None
    # semaphore indicating how many threads are ready right now to grab a command
    ready_threads = None
    command_list = None  # store the commands that need to be handled
    command_list_read_lock = None  # just for reading the list
    command_list_write_lock = None  # for writing the list
    shutdown_flag = False

    def __init__(self, bridge_conn):
        self.thread_count = 0
        self.bridge_conn = bridge_conn
        self.ready_threads = threading.Semaphore(0)  # start the ready threads at 0
        self.command_list = list()
        self.command_list_read_lock = threading.Lock()
        self.command_list_write_lock = threading.Lock()

    def handle_command(self, msg_dict):
        """Give the threadpool a command to handle"""
        # test if there are ready_threads waiting
        if not self.ready_threads.acquire(blocking=False):
            # no ready threads waiting - create a new one
            self.thread_count += 1
            self.bridge_conn.logger.debug(
                "Creating thread - now {} threads".format(self.thread_count)
            )
            new_handler = BridgeCommandHandlerThread(self)
            new_handler.start()
        else:
            self.ready_threads.release()

        # take out the write lock, we're adding to the list
        with self.command_list_write_lock:
            self.command_list.append(msg_dict)
            # the next ready thread will grab the command

    def get_command(self):
        """Threads ask for commands to handle - a thread stuck waiting here is counted in the ready threads"""
        # release increments the ready threads count
        self.ready_threads.release()

        try:
            while not self.shutdown_flag and not GLOBAL_BRIDGE_SHUTDOWN:
                # get the read lock, so we can see if there's anything to do
                with self.command_list_read_lock:
                    if len(self.command_list) > 0:
                        # yes! grab the write lock (only thing that can have the write lock without the read lock is commands being added, so we won't deadlock/have to wait long)
                        with self.command_list_write_lock:
                            # yes! give back the first command
                            return self.command_list.pop()
                # wait a little before we try again
                time.sleep(0.01)
        finally:
            # make sure the thread "acquires" the semaphore (decrements the ready_threads count)
            self.ready_threads.acquire(blocking=False)

        # if we make it here, we're shutting down. return none and the thread will pack it in
        return None

    def __del__(self):
        """We're done with this threadpool, tell the threads to start packing it in"""
        self.shutdown_flag = True


class BridgeReceiverThread(threading.Thread):
    """class to handle running a thread to receive bridge commands/responses and direct accordingly"""

    # If we don't know how to handle the version, reply back with an error and the highest version we do support
    ERROR_UNSUPPORTED_VERSION = json.dumps(
        {
            ERROR: True,
            MAX_VERSION: MAX_SUPPORTED_COMMS_VERSION,
            MIN_VERSION: MIN_SUPPORTED_COMMS_VERSION,
        }
    )

    def __init__(self, bridge_conn):
        super(BridgeReceiverThread, self).__init__()

        self.bridge_conn = bridge_conn

        # don't let the recv loop keep us alive
        self.daemon = True

    def run(self):
        # threadpool to handle creating/running threads to handle commands
        threadpool = BridgeCommandHandlerThreadPool(self.bridge_conn)

        while not GLOBAL_BRIDGE_SHUTDOWN:
            try:
                data = read_size_and_data_from_socket(self.bridge_conn.get_socket())
            except socket.timeout:
                # client didn't have anything to say - just wait some more
                time.sleep(0.1)
                continue
            except (BridgeClosedException, ConnectionResetError):
                break  # expected - the other side has closed the connection

            try:
                msg_dict = json.loads(data.decode("utf-8"))
                self.bridge_conn.logger.debug("Recv loop received {}".format(msg_dict))

                if can_handle_version(msg_dict):
                    if msg_dict[TYPE] in [RESULT, ERROR]:
                        # handle a response or error
                        self.bridge_conn.add_response(msg_dict)
                    else:
                        # queue this and hand off to a worker threadpool
                        threadpool.handle_command(msg_dict)
                else:
                    # bad version
                    self.bridge_conn.send_data(
                        BridgeReceiverThread.ERROR_UNSUPPORTED_VERSION
                    )
            except EXCEPTION_TYPES as e:
                # eat exceptions and continue, don't want a bad message killing the recv loop
                self.bridge_conn.logger.exception(e)

        self.bridge_conn.logger.debug("Receiver thread shutdown")


class BridgeCommandHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """handle a new client connection coming in - continue trying to read/service requests in a loop until we fail to send/recv"""
        # if we're getting debug logs, also record a profile for serving each client connection. Little bit gross to combine the two concepts, but they're related and saves having to add another flag
        pr = None
        if self.server.bridge.logger.level == logging.DEBUG:
            pr = cProfile.Profile()
            pr.enable()

        peer = self.request.getpeername()
        self.server.bridge.logger.warn("Handling connection from {}".format(peer))
        try:
            # run the recv loop directly
            BridgeReceiverThread(
                BridgeConn(
                    self.server.bridge,
                    self.request,
                    response_timeout=self.server.bridge.response_timeout,
                )
            ).run()

            # only get here if the client has closed the connection/requested shutdown
            if GLOBAL_BRIDGE_SHUTDOWN:
                self.server.bridge.logger.debug(
                    "Receiver thread exited - bridge shutdown requested"
                )
                self.server.bridge.shutdown()

        except EXCEPTION_TYPES as e:
            # something weird went wrong?
            self.server.bridge.logger.exception(e)
        finally:
            if self.server.bridge is not None:
                self.server.bridge.logger.warn(
                    "Closing connection from {}".format(peer)
                )

            if pr is not None:
                p = pstats.Stats(pr)
                p.sort_stats("cumulative")
                p.print_stats()  # gross that we can't log this instead of printing, but that's just python for you :(

            # we're out of the loop now, so the connection object will get told to delete itself, which will remove its references to any objects its holding onto


class BridgeHandle(object):
    def __init__(self, local_obj):
        self.handle = str(uuid.uuid4())
        self.local_obj = local_obj
        self.attrs = dir(local_obj)

    def to_dict(self):
        # extract the type name from the repr for the type
        type_repr = repr(type(self.local_obj))
        # expect it to be something like <class 'foo.bar'> or <type 'foo.bar'>
        if "'" in type_repr:
            type_name = type_repr.split("'")[1]
        else:
            # just use the repr straight up
            type_name = type_repr
        return {
            HANDLE: self.handle,
            TYPE: type_name,
            ATTRS: self.attrs,
            REPR: repr(self.local_obj),
        }

    def __str__(self):
        return "BridgeHandle({}: {})".format(self.handle, self.local_obj)


class BridgeResponse(object):
    """Utility class for waiting for and receiving responses"""

    event = None  # used to flag whether the response is ready
    response = None

    def __init__(self, response_id):
        self.event = threading.Event()
        self.response_id = response_id  # just for tracking, so we can report it in timeout exception if needed

    def set(self, response):
        """store response data, and let anyone waiting know it's ready"""
        self.response = response
        # trigger the event
        self.event.set()

    def get(self, timeout=None):
        """wait for the response"""
        if timeout is not None and timeout < 0:
            # can't pass in None higher up reliably, as it gets used to indicate "default timeout".
            # Instead, treat a negative timeout as "wait forever", and set timeout to None, so event.wait
            # will wait forever.
            timeout = None

        if not self.event.wait(timeout):
            raise BridgeTimeoutException(
                "Didn't receive response {} before timeout".format(self.response_id)
            )

        return self.response


class BridgeResponseManager(object):
    """Handles waiting for and receiving responses"""

    response_dict = None  # maps response ids to a BridgeResponse
    response_lock = None

    def __init__(self):
        self.response_dict = dict()
        self.response_lock = threading.Lock()

    def add_response(self, response_dict):
        """response received - register it, then set the event for it"""
        with self.response_lock:
            response_id = response_dict[ID]
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse(response_id)

            # set the data and trigger the event
            self.response_dict[response_id].set(response_dict)

    def get_response(self, response_id, timeout=None):
        """Register for a response and wait until received"""
        with self.response_lock:
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse(response_id)
            response = self.response_dict[response_id]

        # wait for the data - will throw a BridgeTimeoutException if doesn't get it by timeout
        data = response.get(timeout)

        if TYPE in data:
            if data[TYPE] == ERROR:
                # problem with the bridge itself, raise an exception
                raise BridgeOperationException(data)

        with self.response_lock:
            # delete the entry, we're done here
            del self.response_dict[response_id]

        return data


class BridgeConn(object):
    """Internal class, representing a connection to a remote bridge that serves our requests"""

    stats = None

    def __init__(
        self,
        bridge,
        sock=None,
        connect_to_host=None,
        connect_to_port=None,
        response_timeout=DEFAULT_RESPONSE_TIMEOUT,
        record_stats=False,
    ):
        """Set up the bridge connection - only instantiates a connection as needed"""
        self.host = connect_to_host
        self.port = connect_to_port

        # get a reference to the bridge's logger for the connection
        self.logger = bridge.logger

        self.handle_dict = {}
        # list of tuples of (handle, time) that have been marked for deletion and the time they were marked at
        # list will always be in order of earliest marked to latest
        self.delay_delete_handles = []

        self.sock = sock
        self.comms_lock = threading.RLock()
        self.handle_lock = threading.RLock()

        self.response_mgr = BridgeResponseManager()
        self.response_timeout = response_timeout

        # keep a cache of types of objects we've created
        # we'll keep all the types forever (including handles to bridgedcallables in them) because types are super-likely
        # to be reused regularly, and we don't want to keep deleting them and then having to recreate them all the time.
        self.cached_bridge_types = dict()

        # if the bridge has requested a local_call_hook/local_eval_hook, record that
        self.local_call_hook = bridge.local_call_hook
        self.local_eval_hook = bridge.local_eval_hook
        self.local_exec_hook = bridge.local_exec_hook

        if record_stats:
            self.stats = Stats()

    def __del__(self):
        """On teardown, make sure we close our socket to the remote bridge"""
        with self.comms_lock:
            if self.sock is not None:
                self.sock.close()

    def create_handle(self, obj):
        bridge_handle = BridgeHandle(obj)

        with self.handle_lock:
            self.handle_dict[bridge_handle.handle] = bridge_handle

        self.logger.debug("Handle created {} for {}".format(bridge_handle.handle, obj))

        return bridge_handle

    def get_object_by_handle(self, handle):
        with self.handle_lock:
            if handle not in self.handle_dict:
                raise Exception("Old/unknown handle {}".format(handle))

            return self.handle_dict[handle].local_obj

    def release_handle(self, handle):
        with self.handle_lock:
            if handle in self.handle_dict:
                # don't release the handle just yet - put it in the delay list
                # this is because some remote_evals end up with objects being released remotely (causing
                # a delete command to be sent) before they're sent back in a response. The delete command
                # beats the response back, and the handle is removed before it can be used in the response
                # causing an error.
                # To avoid this, we'll delay for a response_timeout period to make sure that we got our
                # response back post-delete.
                self.delay_delete_handles.append((handle, time.time()))

            # use this as a good time to purge delayed handles
            self.purge_delay_delete_handles()

    def purge_delay_delete_handles(self):
        """Actually remove deleted handles from the handle dict once they've exceeded the timeout"""
        with self.handle_lock:
            # work out the cutoff time for when we'd delete delayed handles
            delay_exceeded_time = time.time() - self.response_timeout
            # run over delay_delete_handles until it's empty or the times are later than the delay_exceeded_time
            while (
                len(self.delay_delete_handles) > 0
                and self.delay_delete_handles[0][1] <= delay_exceeded_time
            ):
                handle = self.delay_delete_handles[0][0]
                # actually remove the handle
                del self.handle_dict[handle]
                # remove this entry from the list
                self.delay_delete_handles.pop(0)

    def serialize_to_dict(self, data):
        """Generate a dictionary representing the data - this will later be converted to JSON

        If you're packing a mutable container (list/dict) but don't want it to be remotely mutable (e.g., for performance reasons), wrap it in a OneWayList/OneWayDict to indicate that
        """
        serialized_dict = None

        # note: this needs to come before int, because apparently bools are instances of int (but not vice versa)
        if isinstance(data, bool):
            serialized_dict = {TYPE: BOOL, VALUE: str(data)}
        # don't treat py3 enums as ints - pass them as objects
        elif isinstance(data, INTEGER_TYPES) and not isinstance(data, ENUM_TYPE):
            serialized_dict = {TYPE: INT, VALUE: str(data)}
        elif isinstance(data, float):
            serialized_dict = {TYPE: FLOAT, VALUE: str(data)}
        elif isinstance(
            data, STRING_TYPES
        ):  # all strings are coerced to unicode when serialized
            serialized_dict = {
                TYPE: STR,
                VALUE: base64.b64encode(data.encode("utf-8")).decode("utf-8"),
            }
        elif isinstance(data, bytes):  # py3 only, bytestring in 2 is str
            serialized_dict = {
                TYPE: BYTES,
                VALUE: base64.b64encode(data).decode("utf-8"),
            }
        elif isinstance(data, BridgedMutableProxy):
            # passing back a reference to a list/dict on the other side
            serialized_dict = {TYPE: BRIDGED, VALUE: data._bridged_obj._bridge_handle}
        elif isinstance(data, list):
            serialized_dict = {
                TYPE: LIST,
                ARGS: [
                    self.serialize_to_dict(v) for v in data
                ],  # as an optimisation, we pass the initial contents of the list - most of the time, this is all we want, and this way we don't have to get each entry individually
            }

            if not isinstance(data, OneWayList):
                serialized_dict[VALUE] = self.create_handle(
                    data
                ).to_dict()  # we pass a handle to the list, so we can mutate it from the remote side if needed
        elif isinstance(data, tuple):
            serialized_dict = {
                TYPE: TUPLE,  # tuples aren't mutable, so we don't pass a handle
                VALUE: [self.serialize_to_dict(v) for v in data],
            }
        elif isinstance(data, dict):
            serialized_dict = {
                TYPE: DICT,
                ARGS: [
                    {
                        KEY: self.serialize_to_dict(k),
                        VALUE: self.serialize_to_dict(v),
                    }
                    for k, v in data.items()
                ],  # as an optimisation, we pass the initial contents of the dict - most of the time, this is all we want, and this way we don't have to get each entry individually
            }

            if not isinstance(data, OneWayDict):
                serialized_dict[VALUE] = self.create_handle(
                    data
                ).to_dict()  # we pass a handle to the dict, so we can mutate it from the remote side if needed
        elif isinstance(data, slice):
            serialized_dict = {
                TYPE: SLICE,
                VALUE: [
                    self.serialize_to_dict(data.start),
                    self.serialize_to_dict(data.stop),
                    self.serialize_to_dict(data.step),
                ],
            }
        elif isinstance(
            data, EXCEPTION_TYPES
        ):  # will also catch java.lang.Throwable in jython context
            # treat the exception object as an object
            value = self.create_handle(data).to_dict()
            # then wrap the exception specifics around it
            serialized_dict = {
                TYPE: EXCEPTION,
                VALUE: value,
                MESSAGE: self.serialize_to_dict(getattr(data, "message", "")),
            }
        elif isinstance(data, BridgedObject):
            # passing back a reference to an object on the other side
            # e.g., bridge_obj1.do_thing(bridge_obj2)
            serialized_dict = {TYPE: BRIDGED, VALUE: data._bridge_handle}
        elif isinstance(data, type(None)):
            serialized_dict = {TYPE: NONE}
        elif isinstance(data, type(NotImplemented)):
            serialized_dict = {TYPE: NOTIMPLEMENTED}
        elif isinstance(data, functools.partial) and isinstance(
            data.func, BridgedCallable
        ):
            # if it's a partial, possible that it's against a remote function - in that case, instead of sending it back as a BridgedCallable
            # to get remote called back here where we'll issue a call to the original function, we'll send it with the partial's details so
            # it can be reconstructed on the other side (0 round-trips instead of 2 round-trips)
            # TODO do we have to worry about data.func being from a different bridge connection?
            serialized_dict = {
                TYPE: PARTIAL,
                VALUE: self.serialize_to_dict(data.func),
                ARGS: self.serialize_to_dict(data.args),
                KWARGS: self.serialize_to_dict(data.keywords),
            }
        else:
            # it's an object. assign a reference
            obj_type = CALLABLE_OBJ if callable(data) else OBJ
            serialized_dict = {
                TYPE: obj_type,
                VALUE: self.create_handle(data).to_dict(),
            }

        return serialized_dict

    def deserialize_from_dict(self, serial_dict):
        if serial_dict[TYPE] == INT:  # int, long
            return int(serial_dict[VALUE])
        elif serial_dict[TYPE] == FLOAT:
            return float(serial_dict[VALUE])
        elif serial_dict[TYPE] == BOOL:
            return serial_dict[VALUE] == "True"
        elif serial_dict[TYPE] == STR:
            result = base64.b64decode(serial_dict[VALUE]).decode("utf-8")
            # if we're in python 2, result is now a unicode string.
            if sys.version_info[0] == 2:
                try:
                    # We'll try and force it down to a plain string, because there are plenty of cases where plain strings
                    # are expected instead of unicode (e.g., type/module names). If that fails, we'll keep it as unicode.
                    result = str(result)
                except UnicodeEncodeError:
                    # couldn't make it ascii, keep as unicode
                    pass
            return result

        elif serial_dict[TYPE] == BYTES:
            return base64.b64decode(serial_dict[VALUE])
        elif serial_dict[TYPE] == LIST:
            local_cache = [self.deserialize_from_dict(v) for v in serial_dict[ARGS]]
            if VALUE not in serial_dict:
                # this was explictly serialized as a one-way list, so we'll just pass the unpacked list - don't create a bridge handle to allow mutating changes
                return local_cache

            # VALUE present, so get a bridged object to make it mutable
            bridged_obj = self.build_bridged_object(serial_dict[VALUE], callable=False)
            return BridgedListProxy(bridged_obj, local_cache)
        elif serial_dict[TYPE] == TUPLE:
            return tuple(self.deserialize_from_dict(v) for v in serial_dict[VALUE])
        elif serial_dict[TYPE] == DICT:
            # we use OrderedDict for the local cache, just in case the remote side was an OrderedDict, or subclass of it, or from a python that does ordered dicts normally, and the user expects it to matter. This does come at a potential performance hit.
            local_cache = collections.OrderedDict()
            for kv in serial_dict[ARGS]:
                local_cache[
                    self.deserialize_from_dict(kv[KEY])
                ] = self.deserialize_from_dict(kv[VALUE])

            if VALUE not in serial_dict:
                # this was explictly serialized as a one-way dict, so we'll just pass the unpacked dict - don't create a bridge handle to allow mutating changes
                return local_cache

            # VALUE present, so get a bridged object to make it mutable
            bridged_obj = self.build_bridged_object(serial_dict[VALUE], callable=False)
            return BridgedDictProxy(bridged_obj, local_cache)
        elif (
            serial_dict[TYPE] == SLICE
        ):  # we create local slice objects so isinstance(slice) in __getitem__/etc works
            start, stop, step = [
                self.deserialize_from_dict(v) for v in serial_dict[VALUE]
            ]
            result = slice(start, stop, step)
            return result
        elif serial_dict[TYPE] == EXCEPTION:
            raise BridgeException(
                self.deserialize_from_dict(serial_dict[MESSAGE]),
                self.build_bridged_object(serial_dict[VALUE]),
            )
        elif serial_dict[TYPE] == BRIDGED:
            return self.get_object_by_handle(serial_dict[VALUE])
        elif serial_dict[TYPE] == NONE:
            return None
        elif serial_dict[TYPE] == NOTIMPLEMENTED:
            return NotImplemented
        elif serial_dict[TYPE] == PARTIAL:
            func = self.deserialize_from_dict(serial_dict[VALUE])
            args = self.deserialize_from_dict(serial_dict[ARGS])
            if args is None:
                args = ()
            keywords = self.deserialize_from_dict(serial_dict[KWARGS])
            if keywords is None:
                keywords = {}
            return functools.partial(func, *args, **keywords)
        elif serial_dict[TYPE] == OBJ or serial_dict[TYPE] == CALLABLE_OBJ:
            return self.build_bridged_object(
                serial_dict[VALUE], callable=(serial_dict[TYPE] == CALLABLE_OBJ)
            )

        raise Exception("Unhandled data {}".format(serial_dict))

    def get_socket(self):
        with self.comms_lock:
            if self.sock is None:
                self.logger.debug(
                    "Creating socket to {}:{}".format(self.host, self.port)
                )
                # Create a socket (SOCK_STREAM means a TCP socket)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                # spin up the recv loop thread in the background
                BridgeReceiverThread(self).start()

            return self.sock

    def send_data(self, data):
        """Handle shipping the data across the bridge. Locked to prevent multiple sends
        interleaving with each other (e.g., one is halfway through sending it data when
        it returns, GIL gives it up and the other begins sending - causing decode errors
        on the other side"""
        with self.comms_lock:
            sock = self.get_socket()
            # send the data
            write_size_and_data_to_socket(sock, data)

    @stats_time
    def send_cmd(self, command_dict, get_response=True, timeout_override=None):
        """Package and send a command off. If get_response set, wait for the response and return it. Else return none.
        If timeout override set, wait that many seconds, else wait for default response timeout
        """
        cmd_id = str(uuid.uuid4())  # used to link commands and responses
        envelope_dict = {
            VERSION: COMMS_VERSION_6,
            ID: cmd_id,
            TYPE: CMD,
            CMD: command_dict,
            RESPOND: get_response,
        }
        self.logger.debug("Sending {}".format(envelope_dict))
        data = json.dumps(envelope_dict).encode("utf-8")

        self.send_data(data)

        if get_response:
            result = {}
            # wait for the response
            response_dict = self.response_mgr.get_response(
                cmd_id,
                timeout=timeout_override
                if timeout_override is not None
                else self.response_timeout,
            )

            if response_dict is not None:
                if RESULT in response_dict:
                    result = response_dict[RESULT]
            return result
        else:
            return None

    @stats_hit
    def remote_get(self, handle, name):
        self.logger.debug("remote_get: {}.{}".format(handle, name))
        command_dict = {CMD: GET, ARGS: {HANDLE: handle, NAME: name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_get(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        self.logger.debug("local_get: {}.{}".format(handle, name))

        target = self.get_object_by_handle(handle)
        try:
            result = getattr(target, name)
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    @stats_hit
    def remote_set(self, handle, name, value):
        self.logger.debug("remote_set: {}.{} = {}".format(handle, name, value))
        command_dict = {
            CMD: SET,
            ARGS: {HANDLE: handle, NAME: name, VALUE: self.serialize_to_dict(value)},
        }
        self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_set(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        value = self.deserialize_from_dict(args_dict[VALUE])

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_set: {}.{} = {}".format(handle, name, value))
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug(
                    "Falling back:\n\tlocal_set: {}.{} = {}".format(
                        handle, name, args_dict[VALUE]
                    )
                )

        target = self.get_object_by_handle(handle)
        result = None
        try:
            result = setattr(target, name, value)
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()  # TODO - this and other tracebacks, log with info about what's happening

        return result

    @stats_hit
    def remote_call(self, handle, *args, **kwargs):
        self.logger.debug("remote_call: {}({},{})".format(handle, args, kwargs))

        serial_args = self.serialize_to_dict(args)  # args is a tuple, immutable
        serial_kwargs = self.serialize_to_dict(
            OneWayDict(kwargs)
        )  # send kwargs as oneway for better perf - we don't change it in the call
        command_dict = {
            CMD: CALL,
            ARGS: {HANDLE: handle, ARGS: serial_args, KWARGS: serial_kwargs},
        }

        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def remote_call_nonreturn(self, handle, *args, **kwargs):
        """As per remote_call, but without expecting a response"""
        self.logger.debug(
            "remote_call_nonreturn: {}({},{})".format(handle, args, kwargs)
        )

        serial_args = self.serialize_to_dict(args)  # args is a tuple, immutable
        serial_kwargs = self.serialize_to_dict(
            OneWayDict(kwargs)
        )  # send kwargs as oneway for better perf - we don't change it in the call
        command_dict = {
            CMD: CALL,
            ARGS: {HANDLE: handle, ARGS: serial_args, KWARGS: serial_kwargs},
        }

        self.send_cmd(command_dict, get_response=False)

    @stats_hit
    def local_call(self, args_dict):
        handle = args_dict[HANDLE]

        args = self.deserialize_from_dict(args_dict[ARGS])
        kwargs = self.deserialize_from_dict(args_dict[KWARGS])

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_call: {}({},{})".format(handle, args, kwargs))
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug(
                    "Falling back:\n\tlocal_call: {}({},{})".format(
                        handle, args_dict[ARGS], args_dict[KWARGS]
                    )
                )

        result = None
        try:
            target_callable = self.get_object_by_handle(handle)
            # call the target function, or the hook if we've registered one
            if self.local_call_hook is None:
                result = target_callable(*args, **kwargs)
            else:
                result = self.local_call_hook(self, target_callable, *args, **kwargs)
        except EXCEPTION_TYPES as e:
            result = e
            if not isinstance(e, Exception):
                # not an exception type, so it'll be a java throwable
                # just output the string representation at the moment
                # if you want the stack trace, here's where you'd get it from.
                self.logger.warning("Got java.lang.Throwable: {}".format(e))
            # also, don't display StopIteration exceptions, they're totally normal
            elif not isinstance(e, StopIteration):
                traceback.print_exc()

        return result

    @stats_hit
    def remote_del(self, handle):
        self.logger.debug("remote_del {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        try:
            self.send_cmd(command_dict, get_response=False)
        except (ConnectionError, OSError):
            # get a lot of these when shutting down if the bridge connection has already been torn down before the bridged objects are deleted
            # just ignore - we want to know if the other operations fail, but deleting failing we can probably get away with
            pass

    @stats_hit
    def local_del(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_del {}".format(handle))
        self.release_handle(handle)

    @stats_hit
    def remote_import(self, module_name):
        self.logger.debug("remote_import {}".format(module_name))
        command_dict = {CMD: IMPORT, ARGS: {NAME: module_name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_import(self, args_dict):
        name = args_dict[NAME]

        self.logger.debug("local_import {}".format(name))
        result = None
        try:
            result = importlib.import_module(name)
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    @stats_hit
    def remote_get_type(self, handle):
        self.logger.debug("remote_get_type {}".format(handle))
        command_dict = {CMD: TYPE, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_get_type(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_type {}".format(handle))

        target_obj = self.get_object_by_handle(handle)

        try:
            result = type(target_obj)
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    @stats_hit
    def remote_create_type(self, name, bases, dct):
        self.logger.debug("remote_create_type {}, {}, {}".format(name, bases, dct))
        command_dict = {
            CMD: CREATE_TYPE,
            ARGS: {
                NAME: name,
                BASES: self.serialize_to_dict(
                    tuple(bases)
                ),  # bases should be a tuple, enforce that it is so we don't accidentally send a mutable list
                DICT: self.serialize_to_dict(
                    OneWayDict(dct)
                ),  # send the dict as oneway - gets copied when type being created, so no value in sending it mutable
            },
        }
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_create_type(self, args_dict):
        name = str(
            args_dict[NAME]
        )  # type name can't be unicode string in python2 - force to string
        bases = self.deserialize_from_dict(args_dict[BASES])
        dct = self.deserialize_from_dict(args_dict[DICT])

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug(
                    "local_create_type {}, {}, {}".format(name, bases, dct)
                )
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug(
                    "Falling back:\n\tlocal_create_type {}, {}, {}".format(
                        name, args_dict[BASES], args_dict[DICT]
                    )
                )

        result = None

        try:
            result = type(name, bases, dct)
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    @stats_hit
    def remote_get_all(self, handle):
        self.logger.debug("remote_get_all {}".format(handle))
        command_dict = {CMD: GET_ALL, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_get_all(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_all {}".format(handle))

        target_obj = self.get_object_by_handle(handle)
        result = {name: getattr(target_obj, name) for name in dir(target_obj)}

        return result

    @stats_hit
    def remote_isinstance(self, test_object, class_or_tuple):
        self.logger.debug(
            "remote_isinstance({}, {})".format(test_object, class_or_tuple)
        )

        check_class_tuple = None
        # if we're not checking against a tuple, force it into one
        if not _is_bridged_object(class_or_tuple):
            # local - probably a tuple already
            if not isinstance(class_or_tuple, tuple):
                # it's not :X
                raise Exception(
                    "Can't use remote_isinstance on a non-bridged class: {}".format(
                        class_or_tuple
                    )
                )
            else:
                check_class_tuple = class_or_tuple
        else:
            # single bridged, just wrap in a tuple
            check_class_tuple = (class_or_tuple,)

        command_dict = {
            CMD: ISINSTANCE,
            ARGS: self.serialize_to_dict(
                OneWayDict({OBJ: test_object, TUPLE: check_class_tuple})
            ),  # we don't modify this dict, so make it oneway for perf
        }
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    @stats_hit
    def local_isinstance(self, args_dict):
        args = self.deserialize_from_dict(args_dict)
        test_object = args[OBJ]
        check_class_tuple = args[TUPLE]

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug(
                    "local_isinstance({},{})".format(test_object, check_class_tuple)
                )
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug(
                    "Falling back:\n\tlocal_isinstance({})".format(args_dict)
                )

        # make sure every element is a local object on this side
        if _is_bridged_object(test_object):
            raise Exception(
                "Can't use local_isinstance on a bridged object: {}".format(test_object)
            )

        for clazz in check_class_tuple:
            if _is_bridged_object(clazz):
                raise Exception(
                    "Can't use local_isinstance on a bridged class: {}".format(clazz)
                )

        return isinstance(test_object, check_class_tuple)

    @stats_hit
    def remote_eval(self, eval_string, timeout_override=None, **kwargs):
        self.logger.debug("remote_eval({}, {})".format(eval_string, kwargs))

        command_dict = {
            CMD: EVAL,
            ARGS: self.serialize_to_dict(
                OneWayDict({EXPR: eval_string, KWARGS: OneWayDict(kwargs)})
            ),  # we don't modify the outer dict, or the kwargs dict, so make sure they're both oneway
        }
        # Remote eval commands might take a while, so override the timeout value, factor 100 is arbitrary unless an override specified by caller
        if timeout_override is None:
            timeout_override = self.response_timeout * 100
        result = self.send_cmd(command_dict, timeout_override=timeout_override)

        return self.deserialize_from_dict(result)

    @stats_hit
    def local_eval(self, args_dict):
        args = self.deserialize_from_dict(args_dict)

        result = None

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_eval({},{})".format(args[EXPR], args[KWARGS]))
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug("Falling back:\nlocal_eval {}".format(args_dict))

        try:
            """the import __main__ trick allows accessing all the variables that the bridge imports,
            so evals will run within the global context of what started the bridge, and the arguments
            supplied as kwargs will override that"""
            eval_expr = args[EXPR]
            eval_globals = importlib.import_module("__main__").__dict__
            eval_locals = args[KWARGS]
            # do the eval, or defer to the hook if we've registered one
            if self.local_eval_hook is None:
                result = eval(eval_expr, eval_globals, eval_locals)
            else:
                result = self.local_eval_hook(
                    self, eval_expr, eval_globals, eval_locals
                )
            self.logger.debug("local_eval: Finished evaluating")
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    @stats_hit
    def remote_exec(self, exec_string, timeout_override=None, **kwargs):
        self.logger.debug("remote_exec({}, {})".format(exec_string, kwargs))

        command_dict = {
            CMD: EXEC,
            ARGS: self.serialize_to_dict(
                OneWayDict({EXPR: exec_string, KWARGS: OneWayDict(kwargs)})
            ),  # we don't modify the outer dict, or the kwargs dict, so make sure they're both oneway
        }
        # Remote exec commands might take a while, so override the timeout value, factor 100 is arbitrary unless an override specified by caller
        if timeout_override is None:
            timeout_override = self.response_timeout * 100
        result = self.send_cmd(command_dict, timeout_override=timeout_override)

        return self.deserialize_from_dict(result)

    @stats_hit
    def local_exec(self, args_dict):
        args = self.deserialize_from_dict(args_dict)

        result = None

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_exec({},{})".format(args[EXPR], args[KWARGS]))
            except EXCEPTION_TYPES as e:
                self.logger.debug(
                    "Failed to log deserialized arguments: {}\n{}".format(
                        e, traceback.format_exc()
                    )
                )
                self.logger.debug("Falling back:\nlocal_exec {}".format(args_dict))

        try:
            """the import __main__ trick allows accessing all the variables that the bridge imports,
            so execs will run within the global context of what started the bridge, and the arguments
            supplied as kwargs will override that"""
            exec_expr = args[EXPR]
            exec_globals = importlib.import_module("__main__").__dict__
            # unlike remote_eval, we add the kwargs to the globals, because the most common use of remote_exec is to define a function/class, and locals aren't accessible in those definitions
            exec_globals.update(args[KWARGS])
            # do the exec, or defer to the hook if we've registered one
            if self.local_exec_hook is None:
                exec(exec_expr, exec_globals)
            else:
                self.local_exec_hook(self, exec_expr, exec_globals)
            self.logger.debug("local_exec: Finished executing")
        except EXCEPTION_TYPES as e:
            result = e
            traceback.print_exc()

        return result

    def remoteify(self, module_class_or_function, **kwargs):
        """Push a module, class or function definition into the remote python interpreter, and return a handle to it.

        Notes:
            * requires that the class or function code is able to be understood by the remote interpreter (e.g., if it's running python2, the source must be python2 compatible)
            * If remoteify-ing a class, the class can't be defined in a REPL (a limitation of inspect.getsource). You need to define it in a file somewhere.
            * If remoteify-ing a module, it can't do relative imports - they require a package structure which won't exist
            * If remoteify-ing a module, you only get the handle back - it's not installed into the remote or local sys.modules, you need to do that yourself.
            * You can't remoteify a decorated function/class - it'll only get the source for the decorator wrapper, not the original.
        """
        source_string = inspect.getsource(module_class_or_function)
        name = module_class_or_function.__name__

        # random name that'll appear in the __main__ globals to retrieve the remote definition.
        # Used to avoid colliding with other uses of the name that might be there, or other clients
        temp_name = "_bridge_remoteify_temp_result" + "".join(
            [random.choice("0123456789ABCDEF") for _ in range(0, 8)]
        )

        if isinstance(module_class_or_function, types.ModuleType):
            """Modules need a bit of extra love and care."""
            # We'll use the temp_name to store the source of the module (makes it easier than patching it into the format string below and escaping everything),
            # and pass it as a global to the exec
            kwargs[temp_name] = source_string

            # We create a new module context to execute the module code in, then run a second exec from
            # the first exec inside the new module's __dict__, so imports are set correctly as globals of the module (not globals of the exec)
            # Note that we need to force the module name to be a string - python2 doesn't support unicode module names
            source_string = "import types\nnew_mod = types.ModuleType(str('{name}'))\nexec({temp_name}, new_mod.__dict__)\n".format(
                name=name, temp_name=temp_name
            )
            # update name to capture the new module object we've created
            name = "new_mod"

        elif (
            source_string[0] in " \t"
        ):  # modules won't be indented, only a class/function issue
            # source is indented to some level, so dedent it to avoid an indentation error
            source_string = textwrap.dedent(source_string)

        retrieval_string = "\nglobals()['{temp_name}'] = {name}".format(
            temp_name=temp_name, name=name
        )

        # run the exec
        self.remote_exec(source_string + retrieval_string, **kwargs)

        # retrieve from __main__ with remote_eval
        result = self.remote_eval(temp_name)

        # nuke the temp name - the remote handle will keep the module/class/function around
        self.remote_exec(
            "global {temp_name}\ndel {temp_name}".format(temp_name=temp_name)
        )

        return result

    @stats_hit
    def remote_shutdown(self):
        self.logger.debug("remote_shutdown")
        result = self.deserialize_from_dict(self.send_cmd({CMD: SHUTDOWN}))

        if SHUTDOWN in result and result[SHUTDOWN]:
            # shutdown received - as a gross hack, send a followup that we don't expect to return, to unblock some loops and actually let things shutdown
            self.send_cmd({CMD: SHUTDOWN}, get_response=False)

        return result

    @stats_hit
    def local_shutdown(self):
        global GLOBAL_BRIDGE_SHUTDOWN

        self.logger.debug("local_shutdown")

        GLOBAL_BRIDGE_SHUTDOWN = True

        return {SHUTDOWN: True}

    def handle_command(self, message_dict, want_response=True):
        response_dict = {
            VERSION: COMMS_VERSION_6,
            ID: message_dict[ID],
            TYPE: RESULT,
            RESULT: {},
        }

        command_dict = message_dict[CMD]

        if command_dict[CMD] == DEL:
            self.local_del(command_dict[ARGS])  # no result required
        else:
            if command_dict[CMD] == SHUTDOWN:
                # shutdown handled specially - we pass back the response as a non-mutable dict to avoid back and forth creating dicts if not already done
                result = self.local_shutdown()
                if want_response:  # only serialize if we want a response
                    response_dict[RESULT] = self.serialize_to_dict(OneWayDict(result))
            else:
                result = None
                if command_dict[CMD] == GET:
                    result = self.local_get(command_dict[ARGS])
                elif command_dict[CMD] == SET:
                    result = self.local_set(command_dict[ARGS])
                elif command_dict[CMD] == CALL:
                    result = self.local_call(command_dict[ARGS])
                elif command_dict[CMD] == IMPORT:
                    result = self.local_import(command_dict[ARGS])
                elif command_dict[CMD] == TYPE:
                    result = self.local_get_type(command_dict[ARGS])
                elif command_dict[CMD] == CREATE_TYPE:
                    result = self.local_create_type(command_dict[ARGS])
                elif command_dict[CMD] == GET_ALL:
                    result = self.local_get_all(command_dict[ARGS])
                elif command_dict[CMD] == ISINSTANCE:
                    result = self.local_isinstance(command_dict[ARGS])
                elif command_dict[CMD] == EVAL:
                    result = self.local_eval(command_dict[ARGS])
                elif command_dict[CMD] == EXEC:
                    result = self.local_exec(command_dict[ARGS])

                if want_response:  # only serialize if we want a response
                    response_dict[RESULT] = self.serialize_to_dict(result)

        if want_response:
            self.logger.debug("Responding with {}".format(response_dict))
            return json.dumps(response_dict).encode("utf-8")
        else:
            return None

    def get_bridge_type(self, bridged_obj_dict, callable=False):
        # Get a dynamic bridging type from the cache based on the type name, or create it based on the type recovered from the instance bridge handle
        bridge_handle = bridged_obj_dict[HANDLE]
        type_name = bridged_obj_dict[TYPE]

        # short circuit - any function-like thing, as well as any type (or java.lang.Class) becomes a BridgedCallable (need to invoke types/classes, so they're callable)
        if type_name in [
            "type",
            "java.lang.Class",
            "function",
            "builtin_function_or_method",
            "instancemethod",
            "method_descriptor",
            "wrapper_descriptor",
            "reflectedfunction",  # jython - e.g. jarray.zeros()
        ]:
            return BridgedCallable
        elif type_name in ["module", "javapackage"]:
            return BridgedModule

        # if we've already handled this type, use the old one
        if type_name in self.cached_bridge_types:
            return self.cached_bridge_types[type_name]

        self.logger.debug("Creating type " + type_name)
        # need to create a type
        # grab the remote type for the instance.
        remote_type = self.remote_get_type(bridge_handle)

        # create the class dict by getting any of the methods we're interested in
        class_dict = {}
        for method_name in BRIDGED_CLASS_METHODS:
            if method_name in remote_type._bridge_attrs:
                class_dict[method_name] = remote_type._bridged_get(method_name)

        # handle a python2/3 compatibility issue - 3 uses truediv for /, 2 uses div unless you've imported
        # __future__.division. Allow falling back to __div__ if __truediv__ requested but not present
        if (
            "__div__" in remote_type._bridge_attrs
            and "__truediv__" not in remote_type._bridge_attrs
        ):
            class_dict["__truediv__"] = remote_type._bridged_get("__div__")

        # create the bases - any class level method which requires special implementation needs to add the relevant type
        bases = (BridgedObject,)

        if callable:
            bases = (BridgedCallable,)
        elif (
            "__next__" in remote_type._bridge_attrs
            or "next" in remote_type._bridge_attrs
        ):
            bases = (BridgedIterator,)

        local_type = type(
            str("_bridged_" + type_name), bases, class_dict
        )  # str to force it to non-unicode in py2 (is unicode thanks to unicode_literals)
        self.cached_bridge_types[type_name] = local_type

        return local_type

    def build_bridged_object(self, obj_dict, callable=False):
        # construct a bridgedobject, including getting/creating a local dynamic type for its type
        bridge_type = self.get_bridge_type(obj_dict, callable=callable)

        return bridge_type(self, obj_dict)

    def get_stats(self):
        """Get a copy of the statistics accumulated in the run of this connection so far. Requires that __init__ was called with
        record_stats=True
        """
        stats = None
        if self.stats is not None:
            stats = self.stats.copy()

        return stats

    @stats_hit
    def add_response(self, msg_dict):
        # Just a wrapper to allow us to record this stat
        self.response_mgr.add_response(msg_dict)


class BridgeServer(
    threading.Thread
):  # TODO - have BridgeServer and BridgeClient share a class
    # TODO - provide some way of capturing server stats, potentially remotely as well?
    """Python2Python RPC bridge server

    Like a thread, so call run() to run directly, or start() to run on a background thread
    """

    is_serving = False
    local_call_hook = None
    local_eval_hook = None
    local_exec_hook = None

    def __init__(
        self,
        server_host=DEFAULT_HOST,
        server_port=0,
        loglevel=None,
        response_timeout=DEFAULT_RESPONSE_TIMEOUT,
        local_call_hook=None,
        local_eval_hook=None,
        local_exec_hook=None,
    ):
        """Set up the bridge.

        server_host/port: host/port to listen on to serve requests. If not specified, defaults to 127.0.0.1:0 (random port - use get_server_info() to find out where it's serving)
        loglevel - what messages to log
        response_timeout - how long to wait for a response before throwing an exception, in seconds
        """
        global GLOBAL_BRIDGE_SHUTDOWN

        super(BridgeServer, self).__init__()

        # init the server
        self.server = ThreadingTCPServer(
            (server_host, server_port), BridgeCommandHandler
        )
        # the server needs to be able to get back to the bridge to handle commands, but we don't want that reference keeping the bridge alive
        self.server.bridge = weakref.proxy(self)
        self.server.timeout = 1
        self.daemon = True

        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL + 1

        self.logger.setLevel(loglevel)
        self.response_timeout = response_timeout

        # if we're starting the server, we need to make sure the flag is set to false
        GLOBAL_BRIDGE_SHUTDOWN = False

        # specify a callable to local_call_hook(bridge_conn, target_callable, *args, **kwargs) or
        # local_eval_hook(bridge_conn, eval_expression, eval_globals_dict, eval_locals_dict) to
        # hook local_call/local_eval to allow inspection/modification of calls/evals (e.g., forcing them onto a particular thread)
        self.local_call_hook = local_call_hook
        self.local_eval_hook = local_eval_hook
        self.local_exec_hook = local_exec_hook

    def get_server_info(self):
        """return where the server is serving on"""
        return self.server.socket.getsockname()

    def run(self):
        self.logger.info(
            "serving! (jfx_bridge v{}, Python {}.{}.{})".format(
                __version__,
                sys.version_info.major,
                sys.version_info.minor,
                sys.version_info.micro,
            )
        )
        self.is_serving = True
        self.server.serve_forever()
        self.logger.info("stopped serving")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_serving:
            self.logger.info("Shutting down bridge")
            self.is_serving = False
            self.server.shutdown()  # shutdown the socket server
            self.server.server_close()


class BridgeClient(object):
    """Python2Python RPC bridge client"""

    local_call_hook = None
    local_eval_hook = None
    local_exec_hook = None
    _bridge = None

    def __init__(
        self,
        connect_to_host=DEFAULT_HOST,
        connect_to_port=DEFAULT_SERVER_PORT,
        loglevel=None,
        response_timeout=DEFAULT_RESPONSE_TIMEOUT,
        hook_import=False,
        record_stats=False,
    ):
        """Set up the bridge client
        connect_to_host/port - host/port to connect to run commands.
        loglevel - what messages to log (e.g., logging.INFO, logging.DEBUG)
        response_timeout - how long to wait for a response before throwing an error, in seconds
        hook_import - set to True to add a hook to the import system to allowing importing remote modules
        """
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL + 1

        self.logger.setLevel(loglevel)

        self.client = BridgeConn(
            self,
            sock=None,
            connect_to_host=connect_to_host,
            connect_to_port=connect_to_port,
            response_timeout=response_timeout,
            record_stats=record_stats,
        )

        if hook_import:
            # add a path_hook for this bridge
            sys.path_hooks.append(BridgedModuleFinderLoader(self).path_hook_fn)
            # add an entry for this bridge client's bridge connection to the paths.
            # We add it at the end, so we only catch imports that no one else wants to handle
            sys.path.append(repr(self.client))
            # TODO make sure we remove the finder when the client is torn down?

        self._bridge = self

    @property
    def bridge(self):
        """for backwards compatibility with old examples using external_bridge.bridge.remote_import/etc,
        before the external bridges just inherited from BridgeClient
        Allow access, but warn about it
        """
        warnings.warn(
            "Using <external_bridge>.bridge to get to remote_import/eval/shutdown is deprecated - just do <external_bridge>.remote_import/etc.",
            DeprecationWarning,
        )
        return self._bridge

    def remote_import(self, module_name):
        return self.client.remote_import(module_name)

    def remote_eval(self, eval_string, timeout_override=None, **kwargs):
        """
        Takes an expression as an argument and evaluates it entirely on the server.
        Example: b.bridge.remote_eval('[ f.name for f in currentProgram.functionManager.getFunctions(True)]')
        If this expression would be evaluated on the client, it would take 2-3 minutes for a binary with ~8k functions due to ~8k roundtrips to call __next__ and ~8k roundtrips to access the name attribute

        Caveats:
        - The expression `[ f for f in currentProgram.functionManager.getFunctions(True)]` still takes roughly a 1  minute to finish. Almost the entire time is spent sending the message to the client. This issue requires a deeper change in the RPC implementation to increase throughput or reduce message size

        To provide arguments into the eval context, supply them as keyword arguments with names matching the names used in the eval string (e.g., remote_eval("x+1", x=2))
        """
        return self.client.remote_eval(
            eval_string, timeout_override=timeout_override, **kwargs
        )

    def remote_exec(self, exec_string, timeout_override=None, **kwargs):
        """Takes python script as a string and executes it entirely on the server.

        To provide arguments into the exec context, supply them as keyword arguments with names matching the names used in the exec string (e.g., remote_exec("print(x)", x="helloworld")).

        Note: the python script must be able to be understood by the remote interpreter (e.g., if it's running python2, the script must be python2 compatible)
        """
        return self.client.remote_exec(
            exec_string, timeout_override=timeout_override, **kwargs
        )

    def remoteify(self, module_class_or_function, **kwargs):
        """Push a module, class or function definition into the remote python interpreter, and return a handle to it.

        Notes:
            * requires that the class or function code is able to be understood by the remote interpreter (e.g., if it's running python2, the source must be python2 compatible)
            * If remoteify-ing a class, the class can't be defined in a REPL (a limitation of inspect.getsource). You need to define it in a file somewhere.
            * If remoteify-ing a module, it can't do relative imports - they require a package structure which won't exist
            * If remoteify-ing a module, you only get the handle back - it's not installed into the remote or local sys.modules, you need to do that yourself.
            * You can't remoteify a decorated function/class - it'll only get the source for the decorator wrapper, not the original.
        """
        return self.client.remoteify(module_class_or_function, **kwargs)

    def remote_shutdown(self):
        return self.client.remote_shutdown()

    def get_stats(self):
        """Get the statistics recorded across the run of this BridgeClient"""
        return self.client.get_stats()


def _is_bridged_object(object):
    """Utility function to detect if an object is bridged or not.

    Not recommended for use outside this class, because it breaks the goal that you shouldn't
    need to know if something is bridged or not
    """
    return hasattr(object, "_bridge_type")


def bridged_isinstance(test_object, class_or_tuple):
    """Utility function to wrap isinstance to handle bridged objects. Behaves as isinstance, but if all the objects/classes
    are bridged, will direct the call over the bridge.

    Currently, don't have a good way of handling a mix of bridge/non-bridge, so will just return false
    """
    # make sure we have the real isinstance, just in case we've overridden it (e.g., with ghidra_bridge namespace)
    builtin_isinstance = None
    try:
        from builtins import isinstance as builtin_isinstance  # python3
    except:
        # try falling back to python2 syntax
        from __builtin__ import isinstance as builtin_isinstance

    result = False

    # force class_or_tuple to be a tuple - just easier that way
    if _is_bridged_object(class_or_tuple):
        # bridged object, so not a tuple
        class_or_tuple = (class_or_tuple,)
    if not builtin_isinstance(class_or_tuple, tuple):
        # local clazz, not a tuple
        class_or_tuple = (class_or_tuple,)

    # now is the test_object bridged or not?
    if _is_bridged_object(test_object):
        # yes - we need to handle.
        # remove any non-bridged classes in the tuple
        new_tuple = tuple(
            clazz for clazz in class_or_tuple if _is_bridged_object(clazz)
        )

        if (
            new_tuple
        ):  # make sure there's still some things left to check - otherwise, just return false without shooting it over the bridge
            result = test_object._bridge_isinstance(new_tuple)
    else:
        # test_object isn't bridged - remove any bridged classes in the tuple and palm it off to isinstance
        new_tuple = tuple(
            clazz for clazz in class_or_tuple if not _is_bridged_object(clazz)
        )

        result = builtin_isinstance(test_object, new_tuple)

    return result


class BridgedObject(object):
    """An object you can only interact with on the opposite side of a bridge"""

    _bridge_conn = None
    _bridge_handle = None
    _bridge_type = None
    _bridge_attrs = None
    # overrides allow you to make changes just in the local bridge object, not against the remote object (e.g., to avoid conflicts with interactive fixups to the remote __main__)
    _bridge_overrides = None

    # list of methods which we don't bridge, but need to have specific names (so we can't use the _bridge prefix for them)
    # TODO decorator to mark a function as local, don't bridge it - then have it automatically fill this out (also needs to work for subclasses)
    _LOCAL_METHODS = [
        "__del__",
        "__str__",
        "__repr__",
        "__dir__",
        "__bool__",
        "__nonzero__",
        "getdoc",
    ]

    # list of attrs that we don't want to waste bridge calls on
    _DONT_BRIDGE = [
        "__mro_entries__",  # ignore mro entries - only being called if we're creating a class based off a bridged object
        # associated with ipython
        "_ipython_canary_method_should_not_exist_",
        "__sizeof__",
    ]

    # list of attrs that we don't want to waste bridge calls on, unless they really are defined in the bridged object
    _DONT_BRIDGE_UNLESS_IN_ATTRS = [
        # associated with ipython
        "_repr_mimebundle_",
        "__init_subclass__",
        # javapackage objects (like the ghidra module) don't have a __delattr__
        "__delattr__",
        # for fmagin's ipyghidra
        "__signature__",
        "__annotations__",
        "__objclass__",
        "__wrapped__",
    ]

    def __init__(self, bridge_conn, obj_dict):
        self._bridge_conn = bridge_conn
        self._bridge_handle = obj_dict[HANDLE]
        self._bridge_type = obj_dict[TYPE]
        self._bridge_attrs = obj_dict[ATTRS]
        self._bridge_repr = obj_dict[REPR]
        self._bridge_overrides = dict()

    def __getattribute__(self, attr):
        if (
            attr.startswith(BRIDGE_PREFIX)
            or attr == "__class__"
            or attr in BridgedObject._DONT_BRIDGE
            or attr in BridgedObject._LOCAL_METHODS
            or (
                attr in BridgedObject._DONT_BRIDGE_UNLESS_IN_ATTRS
                and attr not in self._bridge_attrs
            )
        ):
            # we don't want to bridge this for one reason or another (including it may not exist on the other end),
            # so get the local version, or accept the AttributeError that we'll get if it's not present locally.
            result = object.__getattribute__(self, attr)
        else:
            try:
                result = self._bridged_get(attr)
            except BridgeException as be:
                # unwrap AttributeErrors if they occurred on the other side of the bridge
                if be.args[1]._bridge_type.endswith("AttributeError"):
                    raise AttributeError(be.args[0])
                else:
                    # some other cause - just reraise the exception
                    raise

        return result

    def __setattr__(self, attr, value):
        if attr.startswith(BRIDGE_PREFIX):
            object.__setattr__(self, attr, value)
        else:
            self._bridged_set(attr, value)

    def _bridged_get(self, name):
        if name in self._bridge_overrides:
            return self._bridge_overrides[name]

        return self._bridge_conn.remote_get(self._bridge_handle, name)

    def _bridged_get_all(self):
        """As an optimisation, get all of the attributes at once and store them as overrides.

        Should only use this for objects that are unlikely to have their attributes change values (e.g., imported modules),
        otherwise you won't be able to get the updated values without clearing the override
        """
        attrs_dict = self._bridge_conn.remote_get_all(self._bridge_handle)

        # the result is a dictionary of attributes and their bridged objects. set them as overrides in the bridged object
        for name, value in attrs_dict.items():
            self._bridge_set_override(name, value)

    def _bridged_set(self, name, value):
        if name in self._bridge_overrides:
            self._bridge_overrides[name] = value
        else:
            self._bridge_conn.remote_set(self._bridge_handle, name, value)

    def _bridged_get_type(self):
        """Get a bridged object representing the type of this object"""
        return self._bridge_conn.remote_get_type(self._bridge_handle)

    def _bridge_set_override(self, name, value):
        self._bridge_overrides[name] = value

    def _bridge_clear_override(self, name):
        del self._bridge_overrides[name]

    def _bridge_isinstance(self, bridged_class_or_tuple):
        """check whether this object is an instance of the bridged class (or tuple of bridged classes)"""
        # enforce that the bridged_class_or_tuple elements are actually bridged
        if not _is_bridged_object(bridged_class_or_tuple):
            # might be a tuple
            if isinstance(bridged_class_or_tuple, tuple):
                # check all the elements of the tuple
                for clazz in bridged_class_or_tuple:
                    if not _is_bridged_object(clazz):
                        raise Exception(
                            "Can't use _bridge_isinstance with non-bridged class {}".format(
                                clazz
                            )
                        )
            else:
                # nope :x
                raise Exception(
                    "Can't use _bridge_isinstance with non-bridged class {}".format(
                        bridged_class_or_tuple
                    )
                )

        # cool, arguments are valid
        return self._bridge_conn.remote_isinstance(self, bridged_class_or_tuple)

    def __del__(self):
        if (
            self._bridge_conn is not None
        ):  # only need to del if this was properly init'd
            self._bridge_conn.remote_del(self._bridge_handle)

    def __repr__(self):
        repr_string = "<{}('{}', type={}, handle={})>".format(
            type(self).__name__,
            self._bridge_repr,
            self._bridge_type,
            self._bridge_handle,
        )

        if PYTHON_VERSION == 2:
            # need to make sure we escape any unicode characters, repr expects to return string, not unicode. In py3, we don't have to care
            repr_string = repr_string.encode("unicode_escape")

        return repr_string

    def __dir__(self):
        return dir(super(type(self))) + (
            self._bridge_attrs if self._bridge_attrs else []
        )

    def __bool__(self):
        # py3 vs 2 - __bool__ vs __nonzero__
        return self._bridge_conn.remote_eval("bool(x)", x=self)

    __nonzero__ = __bool__  # handle being run in a py2 environment


class BridgedCallable(BridgedObject):
    # TODO can we further make BridgedClass a subclass of BridgedCallable? How can we detect? Allow us to pull this class/type hack further away from normal calls
    def __new__(cls, bridge_conn, obj_dict, class_init=None):
        """BridgedCallables can also be classes, which means they might be used as base classes for other classes. If this happens,
        you'll essentially get BridgedCallable.__new__ being called with 4 arguments to create the new class
        (instead of 3, for an instance of BridgedCallable).

        We handle this by creating the class remotely, and returning the BridgedCallable to that remote class. Note that the class methods
        (including __init__) will be bridged on the remote end, back to us.

        TODO: note sure what might happen if you define __new__ in a class that has a BridgedCallable as the base class
        """
        if class_init is None:
            # instance __new__
            return super(BridgedCallable, cls).__new__(cls)
        else:
            # want to create a class that's based off the remote class represented by a BridgedCallable (in the bases)
            # [Assumption: BridgedCallable base always first? Not sure what would happen if you had multiple inheritance]
            # ignore cls, it's just BridgedCallable
            # name is the name we want to call the class
            name = bridge_conn
            # bases are what the class inherits from. Assuming the first one is the BridgedCallable
            bases = obj_dict
            # dct is the class dictionary
            dct = class_init
            assert isinstance(bases[0], BridgedCallable)
            # create the class remotely, and return the BridgedCallable back to it
            return bases[0]._bridge_conn.remote_create_type(name, bases, dct)

    def __init__(self, bridge_conn, obj_dict, class_init=None):
        """As with __new__, __init__ may be called as part of a class creation, not just an instance of BridgedCallable. We just ignore that case"""
        if class_init is None:
            super(BridgedCallable, self).__init__(bridge_conn, obj_dict)
            if "_bridge_nonreturn" in self._bridge_attrs:
                # if the attribute is present (even if set to False/None), assume it's nonreturning. Shouldn't be present on anything else
                self._bridge_nonreturn = True

    def __call__(self, *args, **kwargs):
        # if we've marked this callable with _bridge_nonreturn, don't wait for a response
        if getattr(self, "_bridge_nonreturn", False):
            return self._bridge_call_nonreturn(*args, **kwargs)

        return self._bridge_conn.remote_call(self._bridge_handle, *args, **kwargs)

    def _bridge_call_nonreturn(self, *args, **kwargs):
        """Explicitly invoke the call without expecting a response"""
        return self._bridge_conn.remote_call_nonreturn(
            self._bridge_handle, *args, **kwargs
        )

    def __get__(self, instance, owner):
        """Implement descriptor get so that we can bind the BridgedCallable to an object if it's defined as part of a class
        Use functools.partial to return a wrapper to the BridgedCallable with the instance object as the first arg
        """
        return functools.partial(self, instance)


class BridgedIterator(BridgedObject):
    def __next__(self):
        # py2 vs 3 - next vs __next__
        try:
            return self._bridged_get(
                "__next__" if "__next__" in self._bridge_attrs else "next"
            )()
        except BridgeException as e:
            # we expect the StopIteration exception - check to see if that's what we got, and if so, raise locally
            if e.args[1]._bridge_type.endswith("StopIteration"):
                raise StopIteration
            # otherwise, something went bad - reraise
            raise

    next = __next__  # handle being run in a py2 environment


class BridgedModule(BridgedObject):
    """Represent a remote module (or javapackage) to allow for doing normal imports"""

    def __init__(self, bridge_conn, obj_dict):
        BridgedObject.__init__(self, bridge_conn, obj_dict)
        # python3 needs __path__ set (to anything) to treat a module as a package for doing "from foo.bar import flam"
        # we mark the __path__ as the bridge_conn to allow easier detection of the package as a bridged one we might be responsible for
        # strictly speaking, only packages need __path__, but we set it for modules as well so that we don't get heaps of errors on the server
        # side when the import machinery tries to get __path__ for them
        self._bridge_set_override("__path__", [repr(bridge_conn)])
        # allow a spec to be set. javapackages resist having attributes added, so we handle it here
        self._bridge_set_override("__spec__", None)


class BridgedModuleFinderLoader:
    """Add to sys.meta_path - returns itself if it can find a remote module to satisfy the import

    Note: position in sys.meta_path is important - you almost certainly want to add it to the end. Adding it at the start
    could have it say it can load everything, and imports of local modules will instead be filled with remote modules
    """

    def __init__(self, bridge_client):
        """Record the bridge client to use for remote importing"""
        self.bridge_client = bridge_client

    def path_hook_fn(self, path):
        """Called when the import machinery runs over path_hooks - returns itself as a finder if its this bridge connection"""
        if path == repr(self.bridge_client.client):
            return self
        # not us, don't play along
        raise ImportError()

    def find_module(self, fullname, path=None):
        """called by import machinery - fullname is the dotted module name to load. If the module is part of a package, __path__ is from
        the parent package
        """
        if path is not None:
            if repr(self.bridge_client.client) in path:
                # this is coming from a bridged package in our bridge
                return self
            # parent isn't bridged, or is bridged but isn't from our bridge - we can't do anything with this
            return None

        # package/module with no parent. See if it exists on the other side before we get excited
        try:
            self.bridge_client.remote_import(fullname)
            # got something back, so yeah, we can fill it
            return self
        except BridgeException as be:
            exception_type = be.args[1]._bridge_type
            if exception_type.endswith(
                "ModuleNotFoundError"
            ) or exception_type.endswith("ImportError"):
                # ModuleNotFoundError in py3, just ImportError in py2
                # module doesn't exist remotely, we can't help - return None
                return None
            else:
                # something else went wrong with the bridge - reraise the exception so the user can deal with it
                raise be

    def load_module(self, fullname):
        """Called by import machinery - fullname is the dotted module name to load"""
        # if the module is already loaded, just give that back
        if fullname in sys.modules:
            return sys.modules[fullname]

        # get the remote module
        target = self.bridge_client.remote_import(fullname)

        # split out the name so we know
        components = fullname.rsplit(".", 1)
        parent = components[0]
        if len(components) > 1:
            child = components[1]
            # set the child as an override on the parent, so the importlib machinery can set it as an attribute without stuffing up - needed for javapackage
            if parent in sys.modules:
                sys.modules[parent]._bridge_set_override(child, None)

        # set some import machinery fields
        target._bridge_set_override("__loader__", self)
        target._bridge_set_override("__package__", parent)
        # ensure we have an override set on __spec__ for everything, including non-modules (e.g., BridgedCallables on java classes)
        # otherwise, __spec__ gets set by import machinery later, leading to a client handle being pushed into the server, where other
        # clients might get it if they import the same module
        # TODO probably need to check there's nothing else being set against the modules? Or is there a way to reload modules for each new client?
        target._bridge_set_override("__spec__", None)

        # add the module to sys.modules
        sys.modules[fullname] = target

        # hand back the module
        return target


# Get UserDict/UserList for using with the mutable containers
try:
    from UserDict import UserDict  # py2
    from UserList import UserList
except ImportError:
    from collections import UserDict, UserList  # py3


class BridgedMutableProxy(object):
    """Base container for a BridgedObject connected to a remote list/dict, as well as a local cache of the list/dict. When created, we use the local cache for any read operations. Once a write operation is performed, though, we send the write back remotely, and discard the cache - future reads will be against the remote container
    TODO is it worth duplicating the write operations into the cache, or re-reading the cache, so local reads after remote writes don't need to be bridged?

    We combine this with UserDict/UserList to ensure our method wrappers are called for all
    functionality (inheriting from just dict on py2.7 didn't allow us to do **dict style unpacking correctly.
    """

    def __init__(self, bridged_obj, local_cache):
        self._bridged_obj = bridged_obj
        self.data = local_cache  # The core of UserDict/UserList initialisation - note: proper userdict/list initialisation takes a copy of this so the initial data can be released, but we don't need that.

    def __str__(self):
        """Special implementation so logging doesn't recurse with getattr("__str__")
        Provides the [1,2,3]/{"a":1,"b":2} view of the object
        """
        str_val = None
        if self.data is not None:
            str_val = str(self.data)
        else:
            self._bridged_obj._bridge_conn.logger.debug(
                "Local cache has been mutated. Using remote __str__()"
            )

            str_val = str(self._bridged_obj)

        if PYTHON_VERSION == 2:
            # need to make sure we escape any unicode characters, repr expects to return string, not unicode. In py3, we don't have to care
            str_val = str_val.encode("unicode_escape")

        return str_val

    def __repr__(self):
        """Provides a more detailed view of the object than str, including the backing handle, the contents of the local_cache and current contents of the remote state

        e.g., <BridgedDictProxy(<_bridged_dict('{'a': 1, 'c': 4, 'b': 10, 'x': 20}', type=dict, handle=4c6e837b-0767-496a-87a7-7d444ece0966)>, local_cache=OrderedDict([('a', 1), ('c', 4), ('b', 10), ('x', 20)]))>
        or for a modified container
        <BridgedListProxy(<_bridged_list('[3, 6, 7, 3, 5]', type=list, handle=af0e11d8-d036-4ecd-877c-c3dd7eb8858b)>, local_cache=None)>
        """
        # get a repr for the bridged obj - including types, current remote state, and handle
        # note that we don't just use the bridged obj repr, as it saves the original state,
        # which could be confusing for people
        current_remote_state = str(self._bridged_obj)
        bridged_obj_repr = "<{}('{}', type={}, handle={})>".format(
            type(self._bridged_obj).__name__,
            current_remote_state,
            self._bridged_obj._bridge_type,
            self._bridged_obj._bridge_handle,
        )

        repr_string = "<{}({}, local_cache={})>".format(
            type(self).__name__, bridged_obj_repr, repr(self.data)
        )

        if PYTHON_VERSION == 2:
            # need to make sure we escape any unicode characters, repr expects to return string, not unicode. In py3, we don't have to care
            repr_string = repr_string.encode("unicode_escape")

        return repr_string


# we use this to implement partialmethod-like behaviour for older pythons (partialmethod is only in python 3.4+). functools.partial by itself doesn't return something that gets the self parameter added automatically. See https://stackoverflow.com/a/60646628
def partialmeth(func, *args, **keywords):
    def newfunc(*fargs, **fkeywords):
        new_args = list(args)
        new_args.extend(fargs)
        new_keywords = keywords.copy()
        new_keywords.update(fkeywords)
        return func(*new_args, **new_keywords)

    newfunc.func = func
    newfunc.args = args
    newfunc.keywords = keywords
    return newfunc


def _bridged_class_mutate_wrapper(fn_name, instance, *args, **kwargs):
    """Wrapper function around methods that modify the backing container. When this is called, we remove the local cache and pass the call onto the remote backing container"""
    instance._bridged_obj._bridge_conn.logger.debug(
        "Mutating container {} with {}()".format(repr(instance._bridged_obj), fn_name)
    )
    instance.data = None  # TODO do we want to poison this?
    return getattr(instance._bridged_obj, fn_name)(*args, **kwargs)


def _bridged_class_read_wrapper(fn_name, instance, *args, **kwargs):
    """Wrapper function around methods that _don't_ modify the backing container. When this is called, we direct it to the local cache if that's still valid, or pass it onto the remote backing list if a mutate has been called"""
    target_fn = None

    if instance.data is not None:
        try:
            target_fn = getattr(instance.data, fn_name)
        except AttributeError:
            # this happens if we're asking for a method that's not defined on the local cached version (e.g., list.copy()/clear() only exists on py3 lists, so the py2 local version won't have it).
            # Not sure if this will ever happen - you'd need to be sending code to py2 that is actually only py3 compliant, but easy enough to handle as a fallback.
            instance._bridged_obj._bridge_conn.logger.warning(
                "Tried to use local container cache for {} with {}(), but it wasn't defined. Falling back to remote version.".format(
                    repr(instance._bridged_obj), fn_name
                )
            )
            pass
    else:
        instance._bridged_obj._bridge_conn.logger.debug(
            "Container {} has been mutated. Using remote for {}()".format(
                repr(instance._bridged_obj), fn_name
            )
        )

    if target_fn is None:
        target_fn = getattr(instance._bridged_obj, fn_name)

    return target_fn(*args, **kwargs)


def _bridged_list_delslice_handler(instance, slice_start, slice_stop):
    """Handle __delslice__ being present in py2 vs py3 - if we're calling this, we're in py2. Py3 calls of similar behaviour go to __delitem__, which behaves the same on py2 and 3
    This is a mutating method (but we'll let the delitem wrapper handle it).
    Note that if slice step is provided, py2 calls delitem with a slice object instead, so we don't come via here.
    Finally, we could try to see if we're talking py2-py2 and the remote has a delslice method - but instead we'll just presume we're not, and pass a slice object to __delitem__ which has the same effect anyway, for simpler logic
    """
    return getattr(instance, "__delitem__")(slice(slice_start, slice_stop))


def _bridged_list_setslice_handler(instance, slice_start, slice_stop, new_vals):
    """As per _bridged_list_delslice_handler, but for setslice"""
    return getattr(instance, "__setitem__")(slice(slice_start, slice_stop), new_vals)


def _bridged_list_getslice_handler(instance, slice_start, slice_stop):
    """As per _bridged_list_delslice_handler, but for getslice - it's a read-only method"""
    return getattr(instance, "__getitem__")(slice(slice_start, slice_stop))


def _bridged_list_clear_handler(instance):
    """Special-case handler for clear being in py3 lists, but not py2. If we are doing py3 ops on a py2 list, we might call clear - if that happens, we'll manually clear it with a slice delete. For py3 on py3, we just call the remote clear.

    This is a mutating method.
    """
    instance._bridged_obj._bridge_conn.logger.debug(
        "Mutating container {} with clear()".format(repr(instance._bridged_obj))
    )
    instance.data = None  # TODO do we want to poison this?
    try:
        # try calling clear
        getattr(instance._bridged_obj, "clear")()
    except AttributeError:
        # clear doesn't exist, it must be a py2 list. reimplement it
        del instance[:]


def _bridged_dict_ior_handler(instance, new_vals):
    """Special-case handler for __ior__ being in py3 dicts, but not py2. If we are doing py3 ops on a py2 dict, we might call |= - if that happens, we'll manually replicate it with update. For py3 on py3, we just call the remote __ior__.

    This is a mutating method.
    """
    instance._bridged_obj._bridge_conn.logger.debug(
        "Mutating container {} with __ior__()".format(repr(instance._bridged_obj))
    )
    instance.data = None  # TODO do we want to poison this?
    try:
        # try calling ior
        return getattr(instance._bridged_obj, "__ior__")(new_vals)
    except AttributeError:
        # __ior__ doesn't exist, it must be a py2 dict. replicate it with update
        instance.update(new_vals)
        return instance


# we need to have the entries defined in the class directly (otherwise, they'll defer automatically to the list implementation). If they're not hardcoded into the class, establish them with entries in the dict - could either do this via a dynamic type() creation, or with setattr (note, can't update the __dict__ directly since python 3.3)
BRIDGED_LIST_MUTABLE_METHODS = [
    "__delitem__",
    "__iadd__",
    "__imul__",
    "__setitem__",
    "append",
    "extend",
    "insert",
    "pop",
    "remove",
    "reverse",
    "sort",
]
BRIDGED_LIST_READ_METHODS = [
    "__add__",
    "__contains__",
    "__eq__",
    "__getitem__",
    "__getstate__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__iter__",
    "__le__",
    "__len__",
    "__lt__",
    "__mul__",
    "__ne__",
    "__reduce__",
    "__reduce_ex__",
    "__reversed__",
    "__rmul__",
    "__sizeof__",
    "copy",
    "count",
    "index",
]
# note: pickle methods (reduce, reduce_ex, getstate) just pickle the contents of the container, no point pickling the remote handle that likely won't be around

bridged_list_methods = {
    name: partialmeth(_bridged_class_mutate_wrapper, name)
    for name in BRIDGED_LIST_MUTABLE_METHODS
}
bridged_list_methods.update(
    {
        name: partialmeth(_bridged_class_read_wrapper, name)
        for name in BRIDGED_LIST_READ_METHODS
    }
)
# Add the special handlers for deprecated py2 slice methods
bridged_list_methods.update(
    {
        "__delslice__": _bridged_list_delslice_handler,
        "__setslice__": _bridged_list_setslice_handler,
        "__getslice__": _bridged_list_getslice_handler,
    }
)
# Add the special handler for clear to adapt to py2 lists
bridged_list_methods.update(
    {
        "clear": _bridged_list_clear_handler,
    }
)
BridgedListProxy = type(
    str("BridgedListProxy"),
    (
        BridgedMutableProxy,
        UserList,  # We don't really need UserList instead of list, but it uses the same self.data structure as UserDict, so if we do it this way, we can share most of the code.
    ),
    bridged_list_methods,
)

BRIDGED_DICT_MUTABLE_METHODS = [
    "__delitem__",
    "__setitem__",
    "clear",
    "pop",
    "popitem",
    "setdefault",
    "update",
]
BRIDGED_DICT_READ_METHODS = [
    "__contains__",
    "__eq__",
    "__getitem__",
    "__getstate__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__iter__",
    "__le__",
    "__len__",
    "__lt__",
    "__ne__",
    "__or__",
    "__reduce__",
    "__reduce_ex__",
    "__reversed__",
    "__ror__",
    "__sizeof__",
    "copy",
    "fromkeys",
    "get",
    "items",
    "keys",
    "values",
]
bridged_dict_methods = {
    name: partialmeth(_bridged_class_mutate_wrapper, name)
    for name in BRIDGED_DICT_MUTABLE_METHODS
}
bridged_dict_methods.update(
    {
        name: partialmeth(_bridged_class_read_wrapper, name)
        for name in BRIDGED_DICT_READ_METHODS
    }
)
# Add mappings for deprecated py2 dict methods to their py3 counterparts. These would only be called by old py2 code, and the counterparts exist and behave the same in py2
bridged_dict_methods.update(
    {
        "iterkeys": partialmeth(_bridged_class_read_wrapper, "keys"),
        "viewkeys": partialmeth(_bridged_class_read_wrapper, "keys"),
        "iteritems": partialmeth(_bridged_class_read_wrapper, "items"),
        "viewitems": partialmeth(_bridged_class_read_wrapper, "items"),
        "itervalues": partialmeth(_bridged_class_read_wrapper, "values"),
        "viewvalues": partialmeth(_bridged_class_read_wrapper, "values"),
        "has_key": partialmeth(_bridged_class_read_wrapper, "__contains__"),
    }
)

# Add the special handler for __ior__ to adapt to py2 dicts
bridged_dict_methods.update(
    {
        "__ior__": _bridged_dict_ior_handler,
    }
)

BridgedDictProxy = type(
    str("BridgedDictProxy"),
    (
        BridgedMutableProxy,
        UserDict,  # we use userdict instead of dict so we can implement ** style unpacking in py2.7 (if we based off dict, our overridden methods didn't get called in that case)
    ),
    bridged_dict_methods,
)
# Note: we explictly don't pass through class modifying methods (e.g., setattr, delattr, new) for bridgedlist and bridgeddict.


def nonreturn(func):
    """Decorator to simplying marking a function as nonreturning for the bridge"""
    func._bridge_nonreturn = True
    return func
