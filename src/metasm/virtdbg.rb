#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory

module VirtDbg
	VIRTDBGDIR = File.dirname(__FILE__)
	# add it to the ruby library path
	$: << VIRTDBGDIR
end

%w[forensic1394 virtdbg util main system].each { |f|
	require File.join('virtdbg', f)
}

