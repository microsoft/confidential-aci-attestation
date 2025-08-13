import os
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py

class CustomBuild(_build_py):
    """
    Custom build command: builds the C core via make, then includes
    built executables into the Python package.
    """
    def run(self):
        # Determine project root (three levels up) and build C executables there
        here = os.path.abspath(os.path.dirname(__file__))
        project_root = os.path.abspath(os.path.join(here, "../../../"))
        subprocess.check_call(["make", "core"], cwd=project_root)
        # Copy built executables into package directory in build
        pkg_dir = os.path.join(self.build_lib, 'attestation')
        self.mkpath(pkg_dir)
        executables = ['get_attestation_ccf', 'verify_attestation_ccf', 'get_snp_version']
        for exe in executables:
            src = os.path.join(project_root, 'build', exe)
            dst = os.path.join(pkg_dir, exe)
            self.copy_file(src, dst)
        # Continue with standard build
        super().run()

setup(
    name='attestation',
    version='0.2.0',
    description='Python bindings for the SNP attestation C core',
    packages=find_packages(where='.'),
    package_dir={'': '.'},
    package_data={'attestation': ['get_attestation_ccf', 'verify_attestation_ccf', 'get_snp_version']},
    include_package_data=True,
    cmdclass={'build_py': CustomBuild},
    install_requires=[],
    python_requires='>=3.7',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: C',
    ],
)