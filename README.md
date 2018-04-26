[![Build Status](https://travis-ci.org/salesforce/smartACL.svg?branch=master)](https://travis-ci.org/salesforce/smartACL)

# **smartACL** 

## Introduction
A set of tools to work with ACLs. It's strongly recommended to use PyPy (http://doc.pypy.org/en/latest/install.html) as Python compiler for a huge increase in the performance.
 
These tools are divided into:

- [Link](Operational%20Information/README.md#link-introduction):
    - Check flows in one or multiple ACLs.
    - It supports Cisco, Juniper, Force10 and Fortigate* ACLs format.

- [smartCompare](Operational%20Information/README.md#smartcompare-introduction):
    - Analyzes two ACLs and show the difference between them.
    - It supports Cisco and Juniper ACLs

- [smartShadow](Operational%20Information/README.md#smartshadow-introduction):
    - Analyzes an ACL to check if any rule is shadowed or irrelevant.
    - It supports Cisco and Juniper ACLs

- [smartLog](Operational%20Information/README.md#smartlog-introduction):
    - Analyzes **unified diff** files between two (or more) ACLs to find what was really change after perform some modifications.
    - It supports only diff files generated for Cisco ACLs (IOS or Nexus)

If you would like to use smartACL, or any of its components as module, check this doc: [API Documentation](Operational%20Information/API.md)

### Limitations
1.- Port ranges are matched completely. If a rule with a port range is split:
``` 
       - permit 10/8 10/8 range 100-200
       + permit 10/8 10/8 range 100-150
       + permit 10/8 10/8 range 150-200
```

2.- Fortigate limitations:
- Only ICMP/TCP/UDP are fully supported service objects
- For IP service objects, protocol is ignore and they are considered like "ip ACLs"
- Working in "Negated" objects support 
   
This is not going to be matched for the time being by SmartLog or SmartCompare

## PYPY (Optional Step)

PyPy is Python interpreter and JIT compiler. PyPy is focused on speed and 100% compatibility with the CPython.

As this project is focused on speed , using pypy for the code makes sense. All steps for installation are for a Mac.

`brew install PyPy` to install pypy.

You should then see a symlink in your /usr/local/bin directory for PyPy `ls /usr/local/bin | grep pypy`

And assuming you have homebrew setup correctly you should be able to type `pypy` in your terminal and get an interactive interpreter.

`pypy Python 2.7.2 (341e1e3821ff, Jun 07 2012, 15:42:54) [PyPy 1.9.0 with GCC 4.2.1] `

Now we can go ahead and use pypy inside our project.

Inside the directory where you have cloned the smartAcl2 code base create a virtualenv.

`virtualenv -p /usr/local/bin/pypy venv`

activate the virtualenv

`source /path/to/your/virtualenv/bin/activate`

check the python version.

`python --version`

Done , go and run the tools as described in the rest of the project. Agian this is an optional step.

