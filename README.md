CITP-Dissector
=============

Github page http://hossimo.github.com/CITP-Dissector/

Wireshark CITP Lua Disector implements the CITP (Controller Interface Transport Protocol) as described at http://www.citp-protocol.org/.

CITP is used in the event and entertainment industries to allow lighting consoles, media servers and visualizers to interchange operation information with an open protocol. CITP utilizes `TCP:on various ports`, `UDP:4809` and the multicast address `224.0.0.180` in order to operate.

The disector listens to CITP/PINF/PLoc/ListeningTCPPort to dynamicly add the posted port to the CITP disector.

Installing the plugin (Windows)
-------------------------------
* Exit Wireshark
* Copy citp.lua to your wireshark user profiles directory

**Vista / Windows 7 / 8** ``C:\Users\<username>\AppData\Roaming\Wireshark\plugins``

**XP/2000** ``C:\Documents and Settings\<username>\Application Data\Wireshark\plugins``

* Edit or create ``C:\Program Files\Wireshark\init.lua`` or ``C:\Program Files (x86)\Wireshark\init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``


Installing the plugin (OSX / Linux / Unix)
------------------------------------------
* Quit Wireshark
* Copy ``citp.lua`` into ``~/.wireshark/plugins``
* Edit or create ``/etc/wireshark/init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``


Currently Implemented (Many still a work in progress)
=====================================================
* CITP
 * PINF  Peer Information Layer
* MSEX
  * CInf  Client Information Message
 * ELIn  Element Library Information message 1.1 (1.0 and 1.2 NYI)
 * EThn  Element Thumbnail message 1.1
 * GEIn  Get Element Information message
 * GELI Get Element Library Information message
 * GELT Get Element Library Thumbnail message
 * GETh  Get Element Thumbnail message
 * LSta  Layer Status Message
 * MEIn  Media Element Information message
 * Nack  Negative Acknowledge Message
 * RqSt  Request Stream message
 * SInf  Server Information Message  1.0 or 1.1
 * StFr  Stream Frame message
