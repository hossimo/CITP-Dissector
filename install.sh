#!/bin/sh

#  install.sh
#  Overwrite the citp.lua file with this version and backup as needed

DST="${HOME}/.wireshark/plugins/"
SRC="citp.lua"
BAK=-1
OS=$(uname)

if [[ $OS == "Darwin" ]]; then
  DST="${HOME}/.config/wireshark/plugins/"
  echo "* Installing on OSX. setting plugins path to:\n\t$DST"
elif [[ $OS == "Linux" ]]; then
  DST="${HOME}/.wireshark/plugins/"
  echo "Installing on Linux. setting plugins path to:\n\t$DST"
else
  echo "* Unknown OS Name: $OS."
  echo "\tExiting Installer."
  exit
fi

## check for plugins path
if [[ ! -d "$DST" ]]; then
  echo "* Creating plugin path at $DST"
  mkdir -p "$DST"
fi

# check for existing citp.lua file
if [[ -e "${DST}${SRC}" ]]; then
  mv -f "${DST}${SRC}" "${DST}${SRC}.bak"
  BAK=$?
  if [[ $BAK == 0 ]]; then
    echo "* Backed up:"
    echo "  ${DST}${SRC}"
    echo "  to ${DST}${SRC}.bak"
  fi
else
  BAK=0
fi

if [[ $BAK != 0 ]]; then
  echo "* Previous version of $SRC count not be backed up over writing file."
fi

cp -f "$(dirname $0)/${SRC}" "${DST}${SRC}"

if [[ $? == 0 ]]; then
  echo "* Copied $SRC to $DST"
else
  echo "* Copy Failed, possible permission problem."
fi
