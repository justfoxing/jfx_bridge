# Run a test jfx_bridge server for external python environments to interact with
# @author justfoxing

import logging
import subprocess
import sys
import os
import types
import time
from jfx_bridge import bridge

def run_server(server_host=bridge.DEFAULT_HOST, server_port=bridge.DEFAULT_SERVER_PORT, response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT):
    """ Run a jfx_bridge server (forever)
        server_host - what address the server should listen on
        server_port - what port the server should listen on
    """
    bridge.BridgeServer(server_host=server_host,
                        server_port=server_port, loglevel=logging.INFO, response_timeout=response_timeout).run()

def run_script_across_jfx_bridge(script_file, python="python", argstring=""):
    """ Spin up a jfx_bridge server and spawn the script in external python to connect back to it.
        Useful in scripts being triggered from inside a limited python that need to use python3 or
        packages that don't work there

        The called script needs to handle the --connect_to_host and --connect_to_port command-line arguments and use them to start
        a jfx_bridge client to talk back to the server.

        Specify python to control what the script gets run with. Defaults to whatever python is in the shell - if changing, specify a path
        or name the shell can find.
        Specify argstring to pass further arguments to the script when it starts up.
    """

    # spawn a ghidra bridge server - use server port 0 to pick a random port
    server = bridge.BridgeServer(
        server_host="127.0.0.1", server_port=0, loglevel=logging.INFO)
    # start it running in a background thread
    server.start()

    try:
        # work out where we're running the server
        server_host, server_port = server.bridge.get_server_info()

        print("Running " + script_file)

        # spawn an external python process to run against it

        try:
            output = subprocess.check_output("{python} {script} --connect_to_host={host} --connect_to_port={port} {argstring}".format(
                python=python, script=script_file, host=server_host, port=server_port, argstring=argstring), stderr=subprocess.STDOUT, shell=True)
            print(output)
        except subprocess.CalledProcessError as exc:
            print("Failed ({}):{}".format(exc.returncode, exc.output))

        print(script_file + " completed")

    finally:
        # when we're done with the script, shut down the server
        server.bridge.shutdown()

# load some fake modules for the tests to remotely import
sys.modules["test_hook_import_top_level"] = types.ModuleType("test_hook_import_top_level")
sys.modules["test_hook_import_as"] = types.ModuleType("test_hook_import_as")
sys.modules["test_hook_import_from"] = types.ModuleType("test_hook_import_from")
sys.modules["test_hook_import_from"].run_server = run_server
sys.modules["test_hook_import_dotted"] = types.ModuleType("test_hook_import_dotted")
sys.modules["test_hook_import_dotted.child"] = types.ModuleType("test_hook_import_dotted.child")
sys.modules["test_hook_import_dotted"].__path__ = ["fake"]
sys.modules["test_hook_import_dotted"].child = sys.modules["test_hook_import_dotted.child"]
# create a "module" that's not a module, to represent java classes in Jython (which are callables)
sys.modules["test_hook_import_nonmodule"] = run_server

# a callable that's marked nonreturn
@bridge.nonreturn
def nonreturn():
    # would cause a timeout if it wasn't a nonreturn
    time.sleep(10)

if __name__ == "__main__":
    port = int(os.environ.get("TEST_PORT", bridge.DEFAULT_SERVER_PORT))
    run_server(server_port=port, response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT)
