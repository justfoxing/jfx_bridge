import setuptools
import subprocess
import os

with open("README.md", "r") as fh:
    long_description = fh.read()
   
# determine the version, then write it out into the bridge.py file
version = subprocess.check_output("git describe", shell=True).decode("utf-8").strip()
bridge_file_path = os.path.join(os.path.dirname(__file__), "jfx_bridge", "bridge.py")
bridge_data = None
with open(bridge_file_path, "r") as bridge_file:
    bridge_data = bridge_file.read()
bridge_data = bridge_data.replace("__version__ = \"0.0.0\"", "__version__ = \"{}\"".format(version))
with open(bridge_file_path, "w") as bridge_file:
    bridge_file.write(bridge_data)

setuptools.setup(
    name="jfx_bridge",
    version=version,
    author="justfoxing",
    author_email="justfoxingprojects@gmail.com",
    description="RPC bridge to/from Python2/Python3/Jython/etc",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/justfoxing/jfx_bridge",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)