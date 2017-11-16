from distutils.core import setup, Extension


setup(name='syscallreplay',
      version='0.1',
      description='Replay a system call trace through an application',
      packages=['syscallreplay'],
      ext_modules=[Extension('syscallreplay',
                             ['tracereplay.c'])])
