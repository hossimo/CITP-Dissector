CITP-Dissector
=============

Wireshark CITP Lua Disector implements the CITP (Controller Interface Transport Protocol) as described at http://www.citp-protocol.org/.

CITP is used in the event and entertainment industries to allow lighting consoles, media servers and visualizers to interchange operation information with an open protocol. CITP utilizes `TCP:on various ports`, `UDP:4809` and the multicast address `224.0.0.180` in order to operate.

The disector listens to CITP/PINF/PLoc/ListeningTCPPort to dynamicly add the posted port to the CITP disector.

Does my copy of Wireshark have Lua Enabled?
-------------------------------
In order for this plugin to function in Wireshark make sure your copy has been compiled with Lua by checking in Help -> About Wireshark and looking for the text ``with lua 5.x``.

![About Dialog](http://wiki.wireshark.org/Lua?action=AttachFile&do=get&target=lua-about.png)

Check [the wireshark wiki](http://wiki.wireshark.org/Lua) for more information

Installing the plugin (Windows)
-------------------------------
* Download the Zip near the top of the page.
* Exit Wireshark
* Copy citp.lua to your wireshark user profiles directory

**Vista / Windows 7 / 8** ``C:\Users\<username>\AppData\Roaming\Wireshark\plugins``

**XP/2000** ``C:\Documents and Settings\<username>\Application Data\Wireshark\plugins``

* Edit or create ``C:\Program Files\Wireshark\init.lua`` or ``C:\Program Files (x86)\Wireshark\init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``


Installing the plugin (OSX / Linux / Unix)
------------------------------------------
* [Download citp.lua](https://github.com/hossimo/CITP-Dissector/releases)
* Quit Wireshark
* Copy ``citp.lua`` into ``~/.wireshark/plugins``
* Edit or create ``/etc/wireshark/init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``


Currently Implemented (still a work in progress)
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

TCP Ports
=========
Because CITP can use any random TCP port, the dissector does not assign a port by default, but dynamicly based on UDP:PINF:PLoc:ListeningTCPPort fields. Until a PINF packet is processed Wiershark does not know what TCP port for to use for CITP.

To manually add a TCP port in *Tools > Lua > Evaluate* enter the following: ``CITP_add_port(####)`` where ``####`` is the port number that you would like to watch then press *Evaluate* e.g. ``CITP_add_port(6463)``
