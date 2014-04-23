# Setup OS specific variables
# Copyright 2008 Roy Marples <roy@marples.name>

OS!=	case `uname -s` in Linux) echo "Linux";; *) echo "BSD";; esac
include ${MK}/os-${OS}.mk
