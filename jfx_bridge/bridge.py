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
import time
import traceback
import weakref
import functools
import operator

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


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # prevent server threads hanging around and stopping python from closing
    daemon_threads = True


DEFAULT_HOST = "127.0.0.1"
DEFAULT_SERVER_PORT = 4768  # "Gh"

VERSION = "v"
MAX_VERSION = "max_v"
MIN_VERSION = "min_v"
COMMS_VERSION_1 = 1
COMMS_VERSION_2 = 2
COMMS_VERSION_3 = 3
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
GET_BATCH = "get_batch"
CREATE_TYPE = "create_type"
SET = "set"
ISINSTANCE = "isinstance"
CALL = "call"
IMPORT = "import"
DEL = "del"
EVAL = "eval"
EXPR = "expr"
RESULT = "result"
ERROR = "error"
SHUTDOWN = "shutdown"

HANDLE = "handle"
NAME = "name"
ATTRS = "attrs"

KWARGS = "kwargs"

BRIDGE_PREFIX = "_bridge"

# Comms v3 (alpha) changes the bridged object representation to include the type - one day, I'll support backwards compatibility
MIN_SUPPORTED_COMMS_VERSION = COMMS_VERSION_3
MAX_SUPPORTED_COMMS_VERSION = COMMS_VERSION_3

DEFAULT_RESPONSE_TIMEOUT = 2  # seconds

GLOBAL_BRIDGE_SHUTDOWN = False

# BridgedObjects have a little trouble with class methods (e.g., where the method of accessing is not instance.doThing(),  but more like
# type(instance).doThing(instance) - such as __lt__, len(), str().
# To handle this, we define a list of class methods that we want to expose - this is a little gross, I'd like to dynamically do this based on the methods in the
# bridged object's type, but need to come up with a blacklist of things like __class__, __new__, etc which will interfere with the local objects first
BRIDGED_CLASS_METHODS = ["__str__", "__len__", "__iter__"]
# extract methods from operator, so I don't have to type out all the different options
for operator_name in dir(operator):
    # only do the methods that start and end with __, and exclude __new__
    if operator_name.startswith("__") and operator_name.endswith("__") and operator_name != "__new__" and "builtin_function_or_method" in str(type(getattr(operator, operator_name))):
        BRIDGED_CLASS_METHODS.append(operator_name)


class BridgeException(Exception):
    """ An exception happened on the other side of the bridge and has been proxied back here
        The bridge is fine, but the remote code you ran might have had an issue.
    """
    pass


class BridgeOperationException(Exception):
    """ Some issue happened with the operation of the bridge itself. The bridge may not be in a good state """
    pass


class BridgeClosedException(Exception):
    """ The bridge has closed """
    pass


SIZE_FORMAT = "!I"


def write_size_and_data_to_socket(sock, data):
    """ Utility function to pack the size in front of data and send it off """

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
    """ Utility function to keep reading from the socket until we get the desired number of bytes """
    data = b''
    while num_bytes > 0:
        new_data = sock.recv(num_bytes)
        if new_data is None:
            # most likely reason for a none here is the socket being closed on the remote end
            raise BridgeClosedException()
        num_bytes = num_bytes - len(new_data)
        data += new_data

    return data


def read_size_and_data_from_socket(sock):
    """ Utility function to read the size of a data block, followed by all of that data """

    size_bytes = read_exactly(sock, struct.calcsize(SIZE_FORMAT))
    size = struct.unpack(SIZE_FORMAT, size_bytes)[0]

    data = read_exactly(sock, size)
    data = data.strip()

    return data


def can_handle_version(message_dict):
    """ Utility function for checking we know about this version """
    return (message_dict[VERSION] <= MAX_SUPPORTED_COMMS_VERSION) and (message_dict[VERSION] >= MIN_SUPPORTED_COMMS_VERSION)


class BridgeCommandHandlerThread(threading.Thread):
    """ Thread that checks for commands to handle and serves them """

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
                try:
                    result = self.bridge_conn.handle_command(cmd)
                except Exception as e:
                    self.bridge_conn.logger.error(
                        "Unexpected exception for {}: {}\n{}".format(cmd, e, traceback.format_exc()))
                    # pack a minimal error, so the other end doesn't have to wait for a timeout
                    result = json.dumps({VERSION: COMMS_VERSION_3, TYPE: ERROR, ID: cmd[ID], }).encode("utf-8")

                try:
                    write_size_and_data_to_socket(
                        self.bridge_conn.get_socket(), result)
                except socket.error:
                    # Other end has closed the socket before we can respond. That's fine, just ask me to do something then ignore me. Jerk. Don't bother staying around, they're probably dead
                    break

                cmd = self.threadpool.get_command()  # block, waiting for next command
        except ReferenceError:
            # expected, means the connection has been closed and the threadpool cleaned up
            pass


class BridgeCommandHandlerThreadPool(object):
    """ Takes commands and handles spinning up threads to run them. Will keep the threads that are started and reuse them before creating new ones """
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
        self.ready_threads = threading.Semaphore(
            0)  # start the ready threads at 0
        self.command_list = list()
        self.command_list_read_lock = threading.Lock()
        self.command_list_write_lock = threading.Lock()

    def handle_command(self, msg_dict):
        """ Give the threadpool a command to handle """
        # test if there are ready_threads waiting
        if not self.ready_threads.acquire(blocking=False):
            # no ready threads waiting - create a new one
            self.thread_count += 1
            self.bridge_conn.logger.debug(
                "Creating thread - now {} threads".format(self.thread_count))
            new_handler = BridgeCommandHandlerThread(self)
            new_handler.start()
        else:
            self.ready_threads.release()

        # take out the write lock, we're adding to the list
        with self.command_list_write_lock:
            self.command_list.append(msg_dict)
            # the next ready thread will grab the command

    def get_command(self):
        """ Threads ask for commands to handle - a thread stuck waiting here is counted in the ready threads """
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
        """ We're done with this threadpool, tell the threads to start packing it in """
        self.shutdown_flag = True


class BridgeReceiverThread(threading.Thread):
    """ class to handle running a thread to receive bridge commands/responses and direct accordingly """

    # If we don't know how to handle the version, reply back with an error and the highest version we do support
    ERROR_UNSUPPORTED_VERSION = json.dumps(
        {ERROR: True, MAX_VERSION: MAX_SUPPORTED_COMMS_VERSION, MIN_VERSION: MIN_SUPPORTED_COMMS_VERSION})

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
                data = read_size_and_data_from_socket(
                    self.bridge_conn.get_socket())
            except socket.timeout:
                # client didn't have anything to say - just wait some more
                time.sleep(0.1)
                continue

            try:
                msg_dict = json.loads(data.decode("utf-8"))
                self.bridge_conn.logger.debug(
                    "Recv loop received {}".format(msg_dict))

                if can_handle_version(msg_dict):
                    if msg_dict[TYPE] in [RESULT, ERROR]:
                        # handle a response or error
                        self.bridge_conn.response_mgr.add_response(msg_dict)
                    else:
                        # queue this and hand off to a worker threadpool
                        threadpool.handle_command(msg_dict)
                else:
                    # bad version
                    write_size_and_data_to_socket(
                        self.bridge_conn.get_socket(), BridgeReceiverThread.ERROR_UNSUPPORTED_VERSION)
            except Exception as e:
                # eat exceptions and continue, don't want a bad message killing the recv loop
                self.bridge_conn.logger.exception(e)

        self.bridge_conn.logger.debug("Receiver thread shutdown")


class BridgeCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """ handle a new client connection coming in - continue trying to read/service requests in a loop until we fail to send/recv """
        self.server.bridge.logger.warn(
            "Handling connection from {}".format(self.request.getpeername()))
        try:
            # run the recv loop directly
            BridgeReceiverThread(BridgeConn(
                self.server.bridge, self.request, response_timeout=self.server.bridge.response_timeout)).run()

            # only get here if the client has requested we shutdown the bridge
            self.server.bridge.logger.debug("Receiver thread exited - bridge shutdown requested")
            self.server.bridge.shutdown()
        except BridgeClosedException:
            pass  # expected - the client has closed the connection
        except Exception as e:
            # something weird went wrong?
            self.server.bridge.logger.exception(e)
        finally:
            self.server.bridge.logger.warn(
                "Closing connection from {}".format(self.request.getpeername()))
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
        return {HANDLE: self.handle, TYPE: type_name, ATTRS: self.attrs, REPR: repr(self.local_obj)}

    def __str__(self):
        return "BridgeHandle({}: {})".format(self.handle, self.local_obj)


class BridgeResponse(object):
    """ Utility class for waiting for and receiving responses """
    event = None  # used to flag whether the response is ready
    response = None

    def __init__(self):
        self.event = threading.Event()

    def set(self, response):
        """ store response data, and let anyone waiting know it's ready """
        self.response = response
        # trigger the event
        self.event.set()

    def get(self, timeout=None):
        """ wait for the response """
        if not self.event.wait(timeout):
            raise Exception()

        return self.response


class BridgeResponseManager(object):
    """ Handles waiting for and receiving responses """
    response_dict = None  # maps response ids to a BridgeResponse
    response_lock = None

    def __init__(self):
        self.response_dict = dict()
        self.response_lock = threading.Lock()

    def add_response(self, response_dict):
        """ response received - register it, then set the event for it """
        with self.response_lock:
            response_id = response_dict[ID]
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse()

            # set the data and trigger the event
            self.response_dict[response_id].set(response_dict)

    def get_response(self, response_id, timeout=None):
        """ Register for a response and wait until received """
        with self.response_lock:
            if response_id not in self.response_dict:
                # response hasn't been waited for yet. create the entry
                self.response_dict[response_id] = BridgeResponse()
            response = self.response_dict[response_id]

        data = None
        try:
            # wait for the data
            data = response.get(timeout)
        except:
            raise Exception(
                "Didn't receive response {} before timeout".format(response_id))

        if TYPE in data:
            if data[TYPE] == ERROR:
                # problem with the bridge itself, raise an exception
                raise BridgeOperationException(data)

        with self.response_lock:
            # delete the entry, we're done here
            del self.response_dict[response_id]

        return data


class BridgeConn(object):
    """ Internal class, representing a connection to a remote bridge that serves our requests """

    def __init__(self, bridge, sock=None, connect_to_host=None, connect_to_port=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge connection - only instantiates a connection as needed """
        self.host = connect_to_host
        self.port = connect_to_port

        # get a reference to the bridge's logger for the connection
        self.logger = bridge.logger

        self.handle_dict = {}

        self.sock = sock
        self.comms_lock = threading.RLock()
        self.handle_lock = threading.Lock()

        self.response_mgr = BridgeResponseManager()
        self.response_timeout = response_timeout

        # keep a cache of types of objects we've created
        # we'll keep all the types forever (including handles to bridgedcallables in them) because types are super-likely
        # to be reused regularly, and we don't want to keep deleting them and then having to recreate them all the time.
        self.cached_bridge_types = dict()

    def __del__(self):
        """ On teardown, make sure we close our socket to the remote bridge """
        with self.comms_lock:
            if self.sock is not None:
                self.sock.close()

    def create_handle(self, obj):
        bridge_handle = BridgeHandle(obj)

        with self.handle_lock:
            self.handle_dict[bridge_handle.handle] = bridge_handle

        self.logger.debug(
            "Handle created {} for {}".format(bridge_handle.handle, obj))

        return bridge_handle

    def get_object_by_handle(self, handle):
        with self.handle_lock:
            if handle not in self.handle_dict:
                raise Exception("Old/unknown handle {}".format(handle))

            return self.handle_dict[handle].local_obj

    def release_handle(self, handle):
        with self.handle_lock:
            if handle in self.handle_dict:
                del self.handle_dict[handle]

    def serialize_to_dict(self, data):
        serialized_dict = None

        # note: this needs to come before int, because apparently bools are instances of int (but not vice versa)
        if isinstance(data, bool):
            serialized_dict = {TYPE: BOOL, VALUE: str(data)}
        elif isinstance(data, INTEGER_TYPES) and not isinstance(data, ENUM_TYPE):  # don't treat py3 enums as ints - pass them as objects
            serialized_dict = {TYPE: INT, VALUE: str(data)}
        elif isinstance(data, float):
            serialized_dict = {TYPE: FLOAT, VALUE: str(data)}
        elif isinstance(data, STRING_TYPES):  # all strings are coerced to unicode
            serialized_dict = {TYPE: STR, VALUE: base64.b64encode(
                data.encode("utf-8")).decode("utf-8")}
        elif isinstance(data, bytes):  # py3 only, bytestring in 2 is str
            serialized_dict = {TYPE: BYTES,
                               VALUE: base64.b64encode(data).decode("utf-8")}
        elif isinstance(data, list):
            serialized_dict = {TYPE: LIST, VALUE: [
                self.serialize_to_dict(v) for v in data]}
        elif isinstance(data, tuple):
            serialized_dict = {TYPE: TUPLE, VALUE: [
                self.serialize_to_dict(v) for v in data]}
        elif isinstance(data, dict):
            serialized_dict = {TYPE: DICT, VALUE: [{KEY: self.serialize_to_dict(
                k), VALUE: self.serialize_to_dict(v)} for k, v in data.items()]}
        elif isinstance(data, EXCEPTION_TYPES):  # will also catch java.lang.Throwable in jython context
            # treat the exception object as an object
            value = self.create_handle(data).to_dict()
            # then wrap the exception specifics around it
            serialized_dict = {TYPE: EXCEPTION, VALUE: value, MESSAGE: self.serialize_to_dict(
                getattr(data, "message", ""))}
        elif isinstance(data, BridgedObject):
            # passing back a reference to an object on the other side
            # e.g., bridge_obj1.do_thing(bridge_obj2)
            serialized_dict = {TYPE: BRIDGED, VALUE: data._bridge_handle}
        elif isinstance(data, type(None)):
            serialized_dict = {TYPE: NONE}
        elif isinstance(data, type(NotImplemented)):
            serialized_dict = {TYPE: NOTIMPLEMENTED}
        else:
            # it's an object. assign a reference
            obj_type = CALLABLE_OBJ if callable(data) else OBJ
            serialized_dict = {TYPE: obj_type,
                               VALUE: self.create_handle(data).to_dict()}

        return serialized_dict

    def deserialize_from_dict(self, serial_dict):
        if serial_dict[TYPE] == INT:  # int, long
            return int(serial_dict[VALUE])
        elif serial_dict[TYPE] == FLOAT:
            return float(serial_dict[VALUE])
        elif serial_dict[TYPE] == BOOL:
            return serial_dict[VALUE] == "True"
        elif serial_dict[TYPE] == STR:
            return base64.b64decode(serial_dict[VALUE]).decode("utf-8")
        elif serial_dict[TYPE] == BYTES:
            return base64.b64decode(serial_dict[VALUE])
        elif serial_dict[TYPE] == LIST:
            return [self.deserialize_from_dict(v) for v in serial_dict[VALUE]]
        elif serial_dict[TYPE] == TUPLE:
            return tuple(self.deserialize_from_dict(v) for v in serial_dict[VALUE])
        elif serial_dict[TYPE] == DICT:
            result = dict()
            for kv in serial_dict[VALUE]:
                key = self.deserialize_from_dict(kv[KEY])
                value = self.deserialize_from_dict(kv[VALUE])
                result[key] = value

            return result
        elif serial_dict[TYPE] == EXCEPTION:
            raise BridgeException(self.deserialize_from_dict(serial_dict[MESSAGE]), self.build_bridged_object(serial_dict[VALUE]))
        elif serial_dict[TYPE] == BRIDGED:
            return self.get_object_by_handle(serial_dict[VALUE])
        elif serial_dict[TYPE] == NONE:
            return None
        elif serial_dict[TYPE] == NOTIMPLEMENTED:
            return NotImplemented
        elif serial_dict[TYPE] == OBJ or serial_dict[TYPE] == CALLABLE_OBJ:
            return self.build_bridged_object(serial_dict[VALUE], callable=(serial_dict[TYPE] == CALLABLE_OBJ))

        raise Exception("Unhandled data {}".format(serial_dict))

    def get_socket(self):
        with self.comms_lock:
            if self.sock is None:
                self.logger.debug(
                    "Creating socket to {}:{}".format(self.host, self.port))
                # Create a socket (SOCK_STREAM means a TCP socket)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                # spin up the recv loop thread in the background
                BridgeReceiverThread(self).start()

            return self.sock

    def send_cmd(self, command_dict, get_response=True, timeout_override=None):
        """ Package and send a command off. If get_response set, wait for the response and return it. Else return none.
            If timeout override set, wait that many seconds, else wait for default response timeout
        """
        cmd_id = str(uuid.uuid4())  # used to link commands and responses
        envelope_dict = {VERSION: COMMS_VERSION_3,
                         ID: cmd_id,
                         TYPE: CMD,
                         CMD: command_dict}
        self.logger.debug("Sending {}".format(envelope_dict))
        data = json.dumps(envelope_dict).encode("utf-8")

        with self.comms_lock:
            sock = self.get_socket()

        # send the data
        write_size_and_data_to_socket(sock, data)

        if get_response:
            result = {}
            # wait for the response
            response_dict = self.response_mgr.get_response(
                cmd_id, timeout=timeout_override if timeout_override else self.response_timeout)

            if response_dict is not None:
                if RESULT in response_dict:
                    result = response_dict[RESULT]
            return result
        else:
            return None

    def remote_get(self, handle, name):
        self.logger.debug("remote_get: {}.{}".format(handle, name))
        command_dict = {CMD: GET, ARGS: {HANDLE: handle, NAME: name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get(self, args_dict):
        handle = args_dict[HANDLE]
        name = args_dict[NAME]
        self.logger.debug("local_get: {}.{}".format(handle, name))

        target = self.get_object_by_handle(handle)
        try:
            result = getattr(target, name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_set(self, handle, name, value):
        self.logger.debug(
            "remote_set: {}.{} = {}".format(handle, name, value))
        command_dict = {CMD: SET, ARGS: {HANDLE: handle,
                                         NAME: name, VALUE: self.serialize_to_dict(value)}}
        self.deserialize_from_dict(self.send_cmd(command_dict))

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
            except Exception as e:
                self.logger.debug("Failed to log deserialized arguments: {}\n{}".format(e, traceback.format_exc()))
                self.logger.debug(
                    "Falling back:\n\tlocal_set: {}.{} = {}".format(handle, name, args_dict[VALUE]))

        target = self.get_object_by_handle(handle)
        result = None
        try:
            result = setattr(target, name, value)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_call(self, handle, *args, **kwargs):
        self.logger.debug(
            "remote_call: {}({},{})".format(handle, args, kwargs))

        serial_args = self.serialize_to_dict(args)
        serial_kwargs = self.serialize_to_dict(kwargs)
        command_dict = {CMD: CALL, ARGS: {HANDLE: handle,
                                          ARGS: serial_args, KWARGS: serial_kwargs}}

        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_call(self, args_dict):
        handle = args_dict[HANDLE]

        args = self.deserialize_from_dict(args_dict[ARGS])
        kwargs = self.deserialize_from_dict(args_dict[KWARGS])

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug(
                    "local_call: {}({},{})".format(handle, args, kwargs))
            except Exception as e:
                self.logger.debug("Failed to log deserialized arguments: {}\n{}".format(e, traceback.format_exc()))
                self.logger.debug(
                    "Falling back:\n\tlocal_call: {}({},{})".format(handle, args_dict[ARGS], args_dict[KWARGS]))

        result = None
        try:
            target_callable = self.get_object_by_handle(handle)
            result = target_callable(*args, **kwargs)
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

        response = self.serialize_to_dict(result)
        return response

    def remote_del(self, handle):
        self.logger.debug("remote_del {}".format(handle))
        command_dict = {CMD: DEL, ARGS: {HANDLE: handle}}
        try:
            self.send_cmd(command_dict, get_response=False)
        except ConnectionError:
            # get a lot of these when shutting down if the bridge connection has already been torn down before the bridged objects are deleted
            # just ignore - we want to know if the other operations fail, but deleting failing we can probably get away with
            pass

    def local_del(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_del {}".format(handle))
        self.release_handle(handle)

    def remote_import(self, module_name):
        self.logger.debug("remote_import {}".format(module_name))
        command_dict = {CMD: IMPORT, ARGS: {NAME: module_name}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_import(self, args_dict):
        name = args_dict[NAME]

        self.logger.debug("local_import {}".format(name))
        result = None
        try:
            result = importlib.import_module(name)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_get_type(self, handle):
        self.logger.debug(
            "remote_get_type {}".format(handle))
        command_dict = {CMD: TYPE, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get_type(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_type {}".format(handle))

        target_obj = self.get_object_by_handle(handle)

        try:
            result = type(target_obj)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_create_type(self, name, bases, dct):
        self.logger.debug(
            "remote_create_type {}, {}, {}".format(name, bases, dct))
        command_dict = {CMD: CREATE_TYPE, ARGS: {NAME: name, BASES: self.serialize_to_dict(
            bases), DICT: self.serialize_to_dict(dct)}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_create_type(self, args_dict):
        name = str(args_dict[NAME])  # type name can't be unicode string in python2 - force to string
        bases = self.deserialize_from_dict(args_dict[BASES])
        dct = self.deserialize_from_dict(args_dict[DICT])

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_create_type {}, {}, {}".format(name, bases, dct))
            except Exception as e:
                self.logger.debug("Failed to log deserialized arguments: {}\n{}".format(e, traceback.format_exc()))
                self.logger.debug(
                    "Falling back:\n\tlocal_create_type {}, {}, {}".format(name, args_dict[BASES], args_dict[DICT]))

        result = None

        try:
            result = type(name, bases, dct)
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_get_all(self, handle):
        self.logger.debug("remote_get_all {}".format(handle))
        command_dict = {CMD: GET_ALL, ARGS: {HANDLE: handle}}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_get_all(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_all {}".format(handle))

        target_obj = self.get_object_by_handle(handle)
        result = {name: getattr(target_obj, name) for name in dir(target_obj)}

        return self.serialize_to_dict(result)

    def remote_isinstance(self, test_object, class_or_tuple):
        self.logger.debug("remote_isinstance({}, {})".format(
            test_object, class_or_tuple))

        check_class_tuple = None
        # if we're not checking against a tuple, force it into one
        if not _is_bridged_object(class_or_tuple):
            # local - probably a tuple already
            if not isinstance(class_or_tuple, tuple):
                # it's not :X
                raise Exception(
                    "Can't use remote_isinstance on a non-bridged class: {}".format(class_or_tuple))
            else:
                check_class_tuple = class_or_tuple
        else:
            # single bridged, just wrap in a tuple
            check_class_tuple = (class_or_tuple,)

        command_dict = {CMD: ISINSTANCE, ARGS: self.serialize_to_dict(
            {OBJ: test_object, TUPLE: check_class_tuple})}
        return self.deserialize_from_dict(self.send_cmd(command_dict))

    def local_isinstance(self, args_dict):
        args = self.deserialize_from_dict(args_dict)
        test_object = args[OBJ]
        check_class_tuple = args[TUPLE]

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_isinstance({},{})".format(
                    test_object, check_class_tuple))
            except Exception as e:
                self.logger.debug("Failed to log deserialized arguments: {}\n{}".format(e, traceback.format_exc()))
                self.logger.debug(
                    "Falling back:\n\tlocal_isinstance({})".format(args_dict))

        # make sure every element is a local object on this side
        if _is_bridged_object(test_object):
            raise Exception(
                "Can't use local_isinstance on a bridged object: {}".format(test_object))

        for clazz in check_class_tuple:
            if _is_bridged_object(clazz):
                raise Exception(
                    "Can't use local_isinstance on a bridged class: {}".format(clazz))

        result = isinstance(test_object, check_class_tuple)

        return self.serialize_to_dict(result)

    def remote_eval(self, eval_string, timeout_override=None, **kwargs):
        self.logger.debug("remote_eval({}, {})".format(eval_string, kwargs))

        command_dict = {CMD: EVAL, ARGS: self.serialize_to_dict(
            {EXPR: eval_string, KWARGS: kwargs})}
        # Remote eval commands might take a while, so override the timeout value, factor 100 is arbitrary unless an override specified by caller
        if timeout_override is None:
            timeout_override = self.response_timeout * 100
        result = self.send_cmd(command_dict, timeout_override=timeout_override)

        return self.deserialize_from_dict(result)

    def local_eval(self, args_dict):
        args = self.deserialize_from_dict(args_dict)

        result = None

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            try:
                # we want to get log the deserialized values, because they're useful.
                # but this also means a bad repr can break things. So we get ready to
                # catch that and fallback to undeserialized values
                self.logger.debug("local_eval({},{})".format(args[EXPR], args[KWARGS]))
            except Exception as e:
                self.logger.debug("Failed to log deserialized arguments: {}\n{}".format(e, traceback.format_exc()))
                self.logger.debug(
                    "Falling back:\n\local_eval {}".format(args_dict))

        try:
            """ the import __main__ trick allows accessing all the variables that the bridge imports, 
            so evals will run within the global context of what started the bridge, and the arguments 
            supplied as kwargs will override that """
            result = eval(args[EXPR], importlib.import_module('__main__').__dict__, args[KWARGS])
            self.logger.debug("local_eval: Finished evaluating")
        except Exception as e:
            result = e
            traceback.print_exc()

        return self.serialize_to_dict(result)

    def remote_get_batch(self, handle, attrs):
        self.logger.debug("remote_get_batch {}".format(attrs))

        command_dict = {CMD: GET_BATCH, ARGS:
            {HANDLE: handle, ATTRS: attrs}}
        result = self.send_cmd(command_dict)
        return self.deserialize_from_dict(result)

    def local_get_batch(self, args_dict):
        handle = args_dict[HANDLE]
        self.logger.debug("local_get_batch {}".format(handle))

        target_obj = self.get_object_by_handle(handle)
        result = {name: getattr(target_obj, name) for name in args_dict[ATTRS]}

        return self.serialize_to_dict(result)

    def remote_shutdown(self):
        self.logger.debug("remote_shutdown")
        result = self.deserialize_from_dict(self.send_cmd({CMD: SHUTDOWN}))
        print(result)
        if SHUTDOWN in result and result[SHUTDOWN]:
            # shutdown received - as a gross hack, send a followup that we don't expect to return, to unblock some loops and actually let things shutdown
            self.send_cmd({CMD: SHUTDOWN}, get_response=False)

        return result

    def local_shutdown(self):
        global GLOBAL_BRIDGE_SHUTDOWN

        self.logger.debug("local_shutdown")

        GLOBAL_BRIDGE_SHUTDOWN = True

        return self.serialize_to_dict({SHUTDOWN: True})

    def handle_command(self, message_dict):
        response_dict = {VERSION: COMMS_VERSION_3,
                         ID: message_dict[ID],
                         TYPE: RESULT,
                         RESULT: {}}

        command_dict = message_dict[CMD]

        if command_dict[CMD] == GET:
            response_dict[RESULT] = self.local_get(command_dict[ARGS])
        elif command_dict[CMD] == SET:
            response_dict[RESULT] = self.local_set(command_dict[ARGS])
        elif command_dict[CMD] == CALL:
            response_dict[RESULT] = self.local_call(command_dict[ARGS])
        elif command_dict[CMD] == DEL:
            self.local_del(command_dict[ARGS])
        elif command_dict[CMD] == IMPORT:
            response_dict[RESULT] = self.local_import(command_dict[ARGS])
        elif command_dict[CMD] == TYPE:
            response_dict[RESULT] = self.local_get_type(command_dict[ARGS])
        elif command_dict[CMD] == CREATE_TYPE:
            response_dict[RESULT] = self.local_create_type(command_dict[ARGS])
        elif command_dict[CMD] == GET_ALL:
            response_dict[RESULT] = self.local_get_all(command_dict[ARGS])
        elif command_dict[CMD] == GET_BATCH:
            response_dict[RESULT] = self.local_get_batch(command_dict[ARGS])
        elif command_dict[CMD] == ISINSTANCE:
            response_dict[RESULT] = self.local_isinstance(command_dict[ARGS])
        elif command_dict[CMD] == EVAL:
            response_dict[RESULT] = self.local_eval(command_dict[ARGS])
        elif command_dict[CMD] == SHUTDOWN:
            response_dict[RESULT] = self.local_shutdown()

        self.logger.debug("Responding with {}".format(response_dict))
        return json.dumps(response_dict).encode("utf-8")

    def get_bridge_type(self, bridged_obj_dict, callable=False):
        # Get a dynamic bridging type from the cache based on the type name, or create it based on the type recovered from the instance bridge handle
        bridge_handle = bridged_obj_dict[HANDLE]
        type_name = bridged_obj_dict[TYPE]

        # short circuit - any function-like thing, as well as any type (or java.lang.Class) becomes a BridgedCallable (need to invoke types/classes, so they're callable)
        if type_name in ["type", "java.lang.Class", "function", "builtin_function_or_method", "instancemethod", "method_descriptor", "wrapper_descriptor"]:
            return BridgedCallable
        elif type_name == "module":
            return BridgedObject

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
        if "__div__" in remote_type._bridge_attrs and "__truediv__" not in remote_type._bridge_attrs:
            class_dict["__truediv__"] = remote_type._bridged_get("__div__")

        # create the bases - any class level method which requires special implementation needs to add the relevant type
        bases = (BridgedObject,)

        if callable:
            bases = (BridgedCallable, )
        elif "__next__" in remote_type._bridge_attrs or "next" in remote_type._bridge_attrs:
            bases = (BridgedIterator, )

        local_type = type(str("_bridged_" + type_name), bases, class_dict)  # str to force it to non-unicode in py2
        self.cached_bridge_types[type_name] = local_type

        return local_type

    def build_bridged_object(self, obj_dict, callable=False):
        # construct a bridgedobject, including getting/creating a local dynamic type for its type
        bridge_type = self.get_bridge_type(obj_dict, callable=callable)

        return bridge_type(self, obj_dict)


class BridgeServer(threading.Thread):
    """ Python2Python RPC bridge server 

        Like a thread, so call run() to run directly, or start() to run on a background thread
    """

    def __init__(self, server_host=DEFAULT_HOST, server_port=0, loglevel=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge.

            server_host/port: host/port to listen on to serve requests. If not specified, defaults to 127.0.0.1:0 (random port - use get_server_info() to find out where it's serving)
            loglevel - what messages to log
            response_timeout - how long to wait for a response before throwing an exception, in seconds
        """
        super(BridgeServer, self).__init__()

        # init the server
        self.server = ThreadingTCPServer(
            (server_host, server_port), BridgeCommandHandler)
        # the server needs to be able to get back to the bridge to handle commands, but we don't want that reference keeping the bridge alive
        self.server.bridge = weakref.proxy(self)
        self.server.timeout = 1
        self.daemon = True
        self.is_serving = False

        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL+1

        self.logger.setLevel(loglevel)
        self.response_timeout = response_timeout

    def get_server_info(self):
        """ return where the server is serving on """
        return self.server.socket.getsockname()

    def run(self):
        self.logger.info("serving!")
        self.is_serving = True
        self.server.serve_forever()
        self.logger.info("stopped serving")

    def __del__(self):
        self.shutdown()

    def shutdown(self):
        if self.is_serving:
            self.logger.info("Shutting down bridge")
            self.is_serving = False
            self.server.shutdown()
            self.server.server_close()


class BridgeClient(object):
    """ Python2Python RPC bridge client """

    def __init__(self, connect_to_host=DEFAULT_HOST, connect_to_port=DEFAULT_SERVER_PORT, loglevel=None, response_timeout=DEFAULT_RESPONSE_TIMEOUT):
        """ Set up the bridge client
            connect_to_host/port - host/port to connect to run commands. 
            loglevel - what messages to log
            response_timeout - how long to wait for a response before throwing an error, in seconds
        """
        logging.basicConfig()
        self.logger = logging.getLogger(__name__)
        if loglevel is None:  # we don't want any logging - ignore everything
            loglevel = logging.CRITICAL+1

        self.logger.setLevel(loglevel)

        self.client = BridgeConn(
            self, sock=None, connect_to_host=connect_to_host, connect_to_port=connect_to_port, response_timeout=response_timeout)

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
        return self.client.remote_eval(eval_string, timeout_override=timeout_override, **kwargs)

    def remote_shutdown(self):
        return self.client.remote_shutdown()


def _is_bridged_object(object):
    """ Utility function to detect if an object is bridged or not. 

        Not recommended for use outside this class, because it breaks the goal that you shouldn't
        need to know if something is bridged or not
    """
    return hasattr(object, "_bridge_type")


def bridged_isinstance(test_object, class_or_tuple):
    """ Utility function to wrap isinstance to handle bridged objects. Behaves as isinstance, but if all the objects/classes
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
            clazz for clazz in class_or_tuple if _is_bridged_object(clazz))

        if new_tuple:  # make sure there's still some things left to check - otherwise, just return false without shooting it over the bridge
            result = test_object._bridge_isinstance(new_tuple)
    else:
        # test_object isn't bridged - remove any bridged classes in the tuple and palm it off to isinstance
        new_tuple = tuple(
            clazz for clazz in class_or_tuple if not _is_bridged_object(clazz))

        result = builtin_isinstance(test_object, new_tuple)

    return result


class BridgedObject(object):
    """ An object you can only interact with on the opposite side of a bridge """
    _bridge_conn = None
    _bridge_handle = None
    _bridge_type = None
    _bridge_attrs = None
    # overrides allow you to make changes just in the local bridge object, not against the remote object (e.g., to avoid conflicts with interactive fixups to the remote __main__)
    _bridge_overrides = None

    # list of methods which we don't bridge, but need to have specific names (so we can't use the _bridge prefix for them)
    # TODO decorator to mark a function as local, don't bridge it - then have it automatically fill this out (also needs to work for subclasses)
    _LOCAL_METHODS = ["__del__", "__str__", "__repr__", "__dir__", "__bool__", "__nonzero__", "getdoc"]

    # list of attrs that we don't want to waste bridge calls on
    _DONT_BRIDGE = ["__mro_entries__",  # ignore mro entries - only being called if we're creating a class based off a bridged object
                    # associated with ipython
                    "_ipython_canary_method_should_not_exist_",
                    "__sizeof__"]

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
        "__wrapped__"]

    def __init__(self, bridge_conn, obj_dict):
        self._bridge_conn = bridge_conn
        self._bridge_handle = obj_dict[HANDLE]
        self._bridge_type = obj_dict[TYPE]
        self._bridge_attrs = obj_dict[ATTRS]
        self._bridge_repr = obj_dict[REPR]
        self._bridge_overrides = dict()

    def __getattribute__(self, attr):
        if attr.startswith(BRIDGE_PREFIX) or attr == "__class__" or attr in BridgedObject._DONT_BRIDGE or attr in BridgedObject._LOCAL_METHODS or (attr in BridgedObject._DONT_BRIDGE_UNLESS_IN_ATTRS and attr not in self._bridge_attrs):
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
        """ As an optimisation, get all of the attributes at once and store them as overrides.

            Should only use this for objects that are unlikely to have their attributes change values (e.g., imported modules),
            otherwise you won't be able to get the updated values without clearing the override
        """
        attrs_dict = self._bridge_conn.remote_get_all(self._bridge_handle)

        # the result is a dictionary of attributes and their bridged objects. set them as overrides in the bridged object
        for name, value in attrs_dict.items():
            self._bridge_set_override(name, value)

    def _bridged_get_batch(self, attrs, set_override=False):
        attrs_dict = self._bridge_conn.remote_get_batch(self._bridge_handle, attrs)

        if set_override:
            for name, value in attrs_dict.items():
                self._bridge_set_override(name, value)

        return attrs_dict

    def _bridged_set(self, name, value):
        if name in self._bridge_overrides:
            self._bridge_overrides[name] = value
        else:
            self._bridge_conn.remote_set(self._bridge_handle, name, value)

    def _bridged_get_type(self):
        """ Get a bridged object representing the type of this object """
        return self._bridge_conn.remote_get_type(self._bridge_handle)

    def _bridge_set_override(self, name, value):
        self._bridge_overrides[name] = value

    def _bridge_clear_override(self, name):
        del self._bridge_overrides[name]

    def _bridge_isinstance(self, bridged_class_or_tuple):
        """ check whether this object is an instance of the bridged class (or tuple of bridged classes) """
        # enforce that the bridged_class_or_tuple elements are actually bridged
        if not _is_bridged_object(bridged_class_or_tuple):
            # might be a tuple
            if isinstance(bridged_class_or_tuple, tuple):
                # check all the elements of the tuple
                for clazz in bridged_class_or_tuple:
                    if not _is_bridged_object(clazz):
                        raise Exception(
                            "Can't use _bridge_isinstance with non-bridged class {}".format(clazz))
            else:
                # nope :x
                raise Exception(
                    "Can't use _bridge_isinstance with non-bridged class {}".format(bridged_class_or_tuple))

        # cool, arguments are valid
        return self._bridge_conn.remote_isinstance(self, bridged_class_or_tuple)

    def __del__(self):
        if self._bridge_conn is not None:  # only need to del if this was properly init'd
            self._bridge_conn.remote_del(self._bridge_handle)

    def __repr__(self):
        return "<{}('{}', type={}, handle={})>".format(type(self).__name__, self._bridge_repr, self._bridge_type, self._bridge_handle)

    def __dir__(self):
        return dir(super(type(self))) + (self._bridge_attrs if self._bridge_attrs else [])

    def __bool__(self):
        # py3 vs 2 - __bool__ vs __nonzero__
        return self._bridge_conn.remote_eval("bool(x)", x=self)

    __nonzero__ = __bool__  # handle being run in a py2 environment


class BridgedCallable(BridgedObject):
    # TODO can we further make BridgedClass a subclass of BridgedCallable? How can we detect? Allow us to pull this class/type hack further away from normal calls
    def __new__(cls, bridge_conn, obj_dict, class_init=None):
        """ BridgedCallables can also be classes, which means they might be used as base classes for other classes. If this happens,
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
        """ As with __new__, __init__ may be called as part of a class creation, not just an instance of BridgedCallable. We just ignore that case """
        if class_init is None:
            super(BridgedCallable, self).__init__(bridge_conn, obj_dict)

    def __call__(self, *args, **kwargs):
        return self._bridge_conn.remote_call(self._bridge_handle, *args, **kwargs)

    def __get__(self, instance, owner):
        """ Implement descriptor get so that we can bind the BridgedCallable to an object if it's defined as part of a class 
            Use functools.partial to return a wrapper to the BridgedCallable with the instance object as the first arg
        """
        return functools.partial(self, instance)


class BridgedIterator(BridgedObject):
    def __next__(self):
        # py2 vs 3 - next vs __next__
        try:
            return self._bridged_get("__next__" if "__next__" in self._bridge_attrs else "next")()
        except BridgeException as e:
            # we expect the StopIteration exception - check to see if that's what we got, and if so, raise locally
            if e.args[1]._bridge_type.endswith("StopIteration"):
                raise StopIteration
            # otherwise, something went bad - reraise
            raise

    next = __next__  # handle being run in a py2 environment
