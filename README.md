jfx(justfoxing) bridge
=====================
Originally developed as part of https://github.com/justfoxing/ghidra_bridge

jfx_bridge is a simple, single file Python RPC bridge, designed to allow interacting from modern python3 to python2. It was built to operate in constrained interpreters, like the Jython interpreters built into more than one reverse-engineering tool, to allow you to access and interact with the data in the tool, and then use modern python and up-to-date packages to do your work.

The aim is to be as transparent as possible, so once you're set up, you shouldn't need to know if an object is local or from the remote environment - the bridge should seamlessly handle getting/setting/calling against it.

How to use
======================
You might actually want one of the packages that uses jfx_bridge, such as [GhidraBridge](https://github.com/justfoxing/ghidra_bridge).

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
* Needs to be easy to install in constrained tools - no pip install, just add a single directory 
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
