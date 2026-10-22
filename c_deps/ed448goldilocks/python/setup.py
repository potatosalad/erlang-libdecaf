#!/usr/bin/env python

from distutils.command.build import build
from distutils.core import setup

import os
import sys

def libname(ver):
	vars = dict(
	    name='libdecaf',
	    ver=ver,
	)

	if sys.platform == 'darwin':
		return '%(name)s.%(ver)d.dylib' % vars

	return '%(name)s.so.%(ver)d' % vars

class my_build(build):
    def run(self):
        build.run(self)
        if not self.dry_run:
            os.spawnlp(os.P_WAIT, 'sh', 'sh', '-c',
                'cd .. && mkdir build && cd build && cmake .. && make')
            self.copy_file(os.path.join('..', 'build', 'src', libname(0)),
                os.path.join(self.build_lib, 'edgold', 'libdecaf.so'))

cmdclass = {}
cmdclass['build'] = my_build

setup(name='edgold',
      version='1.0',
      description='The Ed ECC Goldilocks Python wrapper',
      author='John-Mark Gurney',
      author_email='jmg@funkthat.com',
      #url='',
      cmdclass=cmdclass,
      packages=['edgold', ],
     )
