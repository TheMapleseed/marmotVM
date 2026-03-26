import os
import sys
import sysconfig
import shutil
import subprocess
from glob import glob

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


class CMakeExtension(Extension):
    def __init__(self, name: str):
        # No sources: CMake generates the shared library.
        super().__init__(name, sources=[])


class CMakeBuild(build_ext):
    def run(self):
        # build_ext.run will call build_extension for each Extension instance.
        super().run()

    def build_extension(self, ext):
        ext_fullpath = self.get_ext_fullpath(ext.name)
        ext_filename = os.path.basename(ext_fullpath)

        build_temp = os.path.abspath(self.build_temp)
        cfg = "Release"
        os.makedirs(build_temp, exist_ok=True)

        # Configure + build once per build directory.
        # We use an out-of-tree build to keep the repo clean.
        cmake_configure_args = [
            "cmake",
            "-S",
            os.path.abspath(os.path.dirname(__file__)),
            "-B",
            build_temp,
            f"-DCMAKE_BUILD_TYPE={cfg}",
            "-DBUILD_PYTHON=ON",
        ]

        # Note: cmake from the `cmake` PyPI package (declared in pyproject)
        # is preferred; this avoids requiring system CMake.
        subprocess.check_call(cmake_configure_args, cwd=build_temp)

        subprocess.check_call(
            ["cmake", "--build", build_temp, "--config", cfg, "--target", "marmotvm_module"],
            cwd=build_temp,
        )

        # Find the built extension file produced by CMake.
        # The target should produce something like: microvm.cpython-312-darwin.so
        matches = glob(os.path.join(build_temp, "**", ext_filename), recursive=True)
        if not matches:
            # Fall back to the extension name without ABI tag (in case the CMake
            # suffix property isn't applied as expected).
            fallback = glob(os.path.join(build_temp, "**", f"{ext.name}*"), recursive=True)
            fallback = [p for p in fallback if os.path.isfile(p)]
            if fallback:
                built_path = fallback[0]
                os.makedirs(os.path.dirname(ext_fullpath), exist_ok=True)
                self.copy_file(built_path, ext_fullpath)
                return
            raise FileNotFoundError(
                f"Could not find built extension {ext_filename}. "
                f"Fallback matches for {ext.name}*: {fallback}"
            )

        built_path = matches[0]

        os.makedirs(os.path.dirname(ext_fullpath), exist_ok=True)
        self.copy_file(built_path, ext_fullpath)


setup(
    name="marmotVM",
    version="0.1.0",
    description="marmotVM - secure custom bytecode virtual machine (C extension)",
    long_description="",
    ext_modules=[CMakeExtension("marmotVM")],
    cmdclass={"build_ext": CMakeBuild},
    zip_safe=False,
)

