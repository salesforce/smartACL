from setuptools import setup

setup(name='smartacl',
      version='3.0',
      description='A set of tools to work with ACLs.',
      url ='https://github.com/salesforce/smartACL',
      author='Alvaro Caso',
      packages=['smartacl'],
      install_requires=[
          'ipaddr==2.2.0',
          'netaddr==0.7.19'],
      zip_safe=False)
