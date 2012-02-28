##
# $Id: download_exec.rb 9488 2010-06-11 16:12:05Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


# these are important 
require 'msf/core'

#this is dependent of your shellcode type (Exec for normal shellcodes without any command shell
require 'msf/core/payload/windows/exec'			

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single
	
	#The Initialization Function
	
	def initialize(info = {})
	
		super(update_info(info,
			'Name'          => 'The Name of Your shellcode',
			'Version'       => '$Revision: 9488 $',
			'Description'   => 'The Discription of your Shellcode',
			'Author'        => 'your name',
			'License'       => BSD_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Privileged'    => false,
			'Payload'       =>
			{
				'Offsets' => { },
				'Payload' =>
					"\xEB\x03\x5B\xEB\x05\xE8\xF8\xFF"+
					
					...
					
					"\xC3"
			}
			))

		# EXITFUNC is not supported :/
		deregister_options('EXITFUNC')

		# Register command execution options
		register_options(
			[
				OptString.new('URL', [ true, "The Discription" ]),
				OptString.new('Filename', [ true, "The Discription" ])
				...
			], self.class)
	end

	#
	# Constructs the payload
	#
	# You can get your parameters from datastore['Your Parameter']
	def generate_stage
		return module_info['Payload']['Payload'] + (datastore['URL'] || '') + "\x90" + (datastore['Filename'] || '') + "\x00"
	end

end
