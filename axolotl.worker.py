#!/usr/bin/env python

"""
Worker script for weechat-axolotl.py - should be placed in
the python subdirectory of the weechat configuration directory.
"""

from pyaxo import Axolotl
import sys
import os

# a method to return a password for the axolotl database
# you can put anything you want here to calculate passwords
# or grab them from a keyring...
def getPasswd(username):
    return username+'123'

location = sys.argv[2]
mynick = sys.argv[3]
username = sys.argv[4]

a = Axolotl(mynick, dbname=location+'/'+username+'.db', dbpassphrase=getPasswd(username))
a.loadState(mynick, username)

if sys.argv[1] == '-e':
    a.encrypt_pipe()
else:
    a.decrypt_pipe()

a.saveState()

