#!/usr/bin/env python

"""
This script will generate a pair of databases for use with the weechat axolotl
plugin. The databases MUST then be SECURELY distributed for use.

You will need to provide your nick and the other party's nick. One database
should be generated per nick pair.

If you want to reinitialize a nick pair, just run the script again.
The old key data will be overwritten in the databases.

Default location for these databases is in the weechat configuration directory.

You should only need to generate and distribute the databases once per
nick pair.

If each party wishes to generate their own database, you can use the 
init_conversations.py script in the utilities directory of the Axolotl 
distribution.
"""

import sys
import binascii
from pyaxo import Axolotl

# modify this as appropriate (also modify axolotl.worker.py to match)
def getPasswd(username):
    return username + '123'

your_nick = raw_input('Your nick for this conversation? ').strip()
other_nick = raw_input('What is the nick of the other party? ').strip()
a = Axolotl(your_nick, dbname=other_nick+'.db', dbpassphrase=getPasswd(other_nick))
b = Axolotl(other_nick, dbname=your_nick+'.db', dbpassphrase=getPasswd(your_nick))
a.initState(other_nick, b.state['DHIs'], b.handshakePKey, b.state['DHRs'], verify=False)
b.initState(your_nick, a.state['DHIs'], a.handshakePKey, a.state['DHRs'], verify=False)

a.saveState()
b.saveState()
print 'The keys for ' + your_nick + ' -> ' + other_nick + ' have been saved in: ' + other_nick + '.db'
print 'The keys for ' + other_nick + ' -> ' + your_nick + ' have been saved in: ' + your_nick + '.db'
