jfx(justfoxing) bridge
=====================
Originally developed as part of https://github.com/justfoxing/ghidra_bridge

jfx_bridge is a simple, single file Python RPC bridge, designed to allow interacting from modern python3 to python2. It was built to operate in constrained interpreters, like the Jython interpreters built into more than one reverse-engineering tool, to allow you to access and interact with the data in the tool, and then use modern python and up-to-date packages to do your work.

The aim is to be as transparent as possible, so once you're set up, you shouldn't need to know if an object is local or from the remote environment - the bridge should seamlessly handle getting/setting/calling against it.

Table of contents
======================
* [How to use](#how-to-use)
* [Security warning](#security-warning)
* [Remote eval](#how-to-use)
* [Long-running commands](#how-to-use)
* [Remote imports](#remote-imports)
* [How it works](#how-it-works)
* [Design principles](#design-principles)
* [Tested](#tested)
* [TODO](#todo)
* [Contributors](#contributors)

How to use
======================
You might actually want one of the packages that uses jfx_bridge, such as [GhidraBridge](https://github.com/justfoxing/ghidra_bridge), [IDABridge](https://github.com/justfoxing/jfx_bridge_ida), or [JEBBridge](https://github.com/justfoxing/jfx_bridge_jeb).

Security warning
=====================
Be aware that when running, a jfx_bridge server effectively provides code execution as a service. If an attacker is able to talk to the port jfx_bridge is running on, they can trivially gain execution with the privileges the server is run with. 

Also be aware that the protocol used for sending and receiving jfx_bridge messages is unencrypted and unverified - a person-in-the-middle attack would allow complete control of the commands and responses, again providing trivial code execution on the server (and with a little more work, on the client). 

By default, the jfx_bridge server only listens on localhost to slightly reduce the attack surface. Only listen on external network addresses if you're confident you're on a network where it is safe to do so. Additionally, it is still possible for attackers to send messages to localhost (e.g., via malicious javascript in the browser, or by exploiting a different process and attacking jfx_bridge to elevate privileges). You can mitigate this risk by running jfx_bridge from a process with reduced permissions (a non-admin user, or inside a container), by only running it when needed, or by running on non-network connected systems.

Remote eval
=====================
jfx_bridge is designed to be transparent, to allow easy porting of non-bridged scripts without too many changes. However, if you're happy to make changes, and you run into slowdowns caused by running lots of remote queries (e.g., something like `for remote_val in remote_iterable: doSomethingRemote()` can be quite slow with a large number of values as each one will result in a message across the bridge), you can make use of the bridge.remote_eval() function to ask for the result to be evaluated on the bridge server all at once, which will require only a single message roundtrip.

The following example demonstrates getting a list of all the names of all the functions in a binary:
```python
import ghidra_bridge 
b = ghidra_bridge.GhidraBridge(namespace=globals())
name_list = b.bridge.remote_eval("[ f.getName() for f in currentProgram.getFunctionManager().getFunctions(True)]")
```

If your evaluation is going to take some time, you might need to use the timeout_override argument to increase how long the bridge will wait before deciding things have gone wrong.

If you need to supply an argument for the remote evaluation, you can provide arbitrary keyword arguments to the remote_eval function which will be passed into the evaluation context as local variables. The following argument passes in a function:
```python
import ghidra_bridge 
b = ghidra_bridge.GhidraBridge(namespace=globals())
func = currentProgram.getFunctionManager().getFunctions(True).next()
mnemonics = b.bridge.remote_eval("[ i.getMnemonicString() for i in currentProgram.getListing().getInstructions(f.getBody(), True)]", f=func)
```
As a simplification, note also that the evaluation context has the same globals loaded into the \_\_main\_\_ of the script that started the server.

Long-running commands
=====================
If you have a particularly slow call in your script, it may hit the response timeout that the bridge uses to make sure the connection hasn't broken. If this happens, you'll see something like `Exception: Didn't receive response <UUID> before timeout`.

There are two options to increase the timeout. When creating the bridge, you can set a timeout value in seconds with the response_timeout argument (e.g., `b = jfx_bridge.bridge.BridgeClient(response_timeout=20)`) which will apply to all commands run across the bridge. Alternatively, if you just want to change the timeout for one command, you can use remote_eval as mentioned above, with the timeout_override argument (e.g., `b.remote_eval("<long running eval>", timeout_override=20)`). If you use the value -1 for either of these arguments, the response timeout will be disabled and the bridge will wait forever for your response to come back - note that this can cause your script to hang if the bridge runs into problems.

Remote imports
=====================
If you want to import modules from the other side (e.g., to access modules only available there), there are two options:
* Use remote_import to get a BridgedModule back directly (e.g., `remote_module = b.remote_import("foo.bar")`). This has the advantage that you have exact control over getting the remote module (and can get remote modules with the same name as local modules) and when it's released, but it does take a little more work.
* Specify hook_import=True when creating the bridge (e.g., `b = jfx_bridge.bridge.BridgeClient(hook_import=True)`). This will add a hook to the import machinery such that, if nothing else can fill the import, the bridge will try to handle it. This allows you to just use the standard `import foo.bar` syntax after you've connected the bridge. This has the advantage that it may be a little easier to use (you still have to make sure the imports happen AFTER the bridge is connected), but it doesn't allow you to import remote modules with the same name as local modules (the local imports take precedence) and it places the remote modules in sys.modules as proper imports, so they and the bridge will likely stay loaded until the process terminates. Additionally, multiple bridges with hook_import=True will attempt to resolve imports in the order they were connected, which may not be the behaviour you want.

How it works
=====================
bridge.py contains a py2/3 compatible python object RPC proxy. One python environment sets up a server on a port, which clients connect to. The bridge provides a handful of commands to carry out remote operations against python objects in the other environment.

A typical first step is remote_import() with a module to load in the target environment. This will make the RPC call to the remote bridge, which will load the module, then create a BridgeHandle to keep it alive and reference it across the bridge. It'll then return it to the local bridge, along with a list of the callable and non-callable attributes of the module.

At the local bridge, this will be deserialized into a BridgedObject, which overrides \_\_getattribute\_\_ and \_\_setattr\_\_ to catch any get/set to the attribute fields, and proxy them back across to the remote bridge, using the bridge handle reference so it knows which module (or other object) we're talking about.

The \_\_getattribute\_\_ override also affects callables, so doing bridged_obj.func() actually returns a BridgedCallable object, which is then invoked (along with any args/kwargs in use). This packs the call parameters off to the remote bridge, which identifies the appropriate object and invokes the call against it, then returns the result.

The bridges are symmetric, so the local bridge is able to send references to local python objects to the remote bridge, and have them used over there, with interactions being sent back to the local bridge (e.g., providing a callback function as an argument works).

Finally, there's a few other miscellaneous features to make life easier - bridged objects which are python iterators/iterables will behave as iterators/iterables in the remote environment, and bridged objects representing types can be inherited from to make your own subclasses of them (note that this will actually create the subclass in the remote environment - this is designed so you can create types to implement Java interfaces for callbacks/listeners/etc in Jython environments, so it was easier to make sure they behave if they're created in the Jython environment).

Design principles
=====================
* Needs to be run in Jython 2.7 and Python 3
* Needs to be easy to install in constrained environments - no pip install, just add a single directory 
(these two requirements ruled out some of the more mature Python RPC projects I looked into)

Tested
=====================
* Automatically tested on Python 3.8.1->Python 2.7

TODO
=====================
* Handle server/client teardown cleanly
* Exceptions - pull traceback info in the exceptions we handle for pushing back
* Better transport/serialization (JSON/TCP just feels wrong)
* Keep stats of remote queries, so users can ID the parts of their scripts causing the most remote traffic for optimisation
* Better threadpool control (don't keep all threads around forever, allow some to die off)

Contributors
=====================
* Thx @fmagin for better iPython support, and much more useful reprs!
* Thanks also to @fmagin for remote_eval, allowing faster remote processing for batch queries!
