CITP-Dissector
=============

Wireshark CITP Lua Disector implimrnts the CITP (Controller Interface Transport Protocol) as described at http://www.citp-protocol.org/.
CITP is used in the event and entertainment industries to allow lighting consoles, media servers and visualizers to interchange operation information with an open protocol. CITP utilizes `TCP`, `UDP:4809` and the multicast address `224.0.0.180` in order to operate.

Installing the plugin (Windows)
-------------------------------
* Exit Wireshark
*Copy citp.lua to your wireshark user profiles directory:
>``Vista/Windows7/8:``

C:\Users\<username>\AppData\Roaming\Wireshark

```XP/2000```

C:\Documents and Settings\<username>\Application Data\Wireshark
* Edit or create ``C:\Program Files\Wireshark\init.lua`` or ``C:\Program Files (x86)\Wireshark\init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``


Installing the plugin (OSX / Linux / Unix)
------------------------------------------
* Quit Wireshark
* Copy ``citp.lua`` into ``~/.wireshark``
* Edit or create ``/etc/wireshark/init.lua`` and change ``disable_lua = true`` to ``disable_lua = false``