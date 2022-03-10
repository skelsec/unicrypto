from setuptools import setup, find_packages
import re

VERSIONFILE="unicrypto/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="unicrypto",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/unicrypto",

	zip_safe=True,
	#
	# license="LICENSE.txt",
	description="Unified interface for cryptographic libraries",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=[
		"Programming Language :: Python :: 3.6",
		"Operating System :: OS Independent",
	],
	
	## these libraries are optional
	## lib can work without additional deps
	install_requires=[
		'pycryptodomex',
	],
)