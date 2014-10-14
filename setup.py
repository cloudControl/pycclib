#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from pycclib.version import __version__

execfile(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pycclib', 'version.py'))

try:
    from setuptools import setup, find_packages
except ImportError:
    import ez_setup
    ez_setup.use_setuptools()
    from setuptools import setup, find_packages

if sys.version_info < (2, 6):
    required = ['simplejson', 'certifi']
else:
    required = ['certifi']

required.append('httplib2>=0.7.4')

setup(
    name='pycclib',
    version=__version__,
    description='Python library for the cloudControl API',
    author='cloudControl Team',
    author_email='info@cloudcontrol.de',
    url='https://www.cloudcontrol.com',
    license='Apache 2.0',
    classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries',
          ],
    packages=find_packages(),
    install_requires=required,
    test_suite='tests',
)
