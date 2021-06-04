format PE GUI
entry start
include 'win32a.inc'

section '.data' data readable writeable
        kernel32 dd ?
        target dd ?

section '.text' code readable writeable executable
        start:
                mov eax, [fs:0x30]
                mov eax, [eax+0x0c]
                mov esi, [eax+0x14]
                lodsd
                xchg esi, eax
                lodsd
                mov eax, [eax+0x10]
                mov [kernel32], eax

                push 0
                push 'ss00'
                sub word[esp+0x2], '0'
                push 'ddre'
                push 'rocA'
                push 'GetP'
                push esp
                push [kernel32]
                call [GetProcAddress]
                mov [target], eax

                push [target]
                call sizeOfFunction

                push ebx
                push PAGE_EXECUTE_READWRITE
                push eax
                push [target]
                call [VirtualProtect]

                push PAGE_EXECUTE_READWRITE
                push MEM_COMMIT or MEM_RESERVE
                push shellcode.size
                push 0
                call [VirtualAlloc]
                mov dword[hook+0x1], eax

                xor ecx, ecx
        searchCall:
                inc ecx
                mov eax, [target]
                add eax, ecx
                mov eax, [eax]
                cmp ax, 0x15FF
                jnz searchCall

                mov ebx, [target]
                add ebx, ecx
                mov eax, [ebx]
                mov [origcode], eax
                add ebx, 2
                mov eax, [ebx]
                mov [origcode+2], eax

                mov ebx, [target]
                add ebx, ecx
                mov eax, [hook]
                mov dword[ebx], eax
                add ebx, 2
                mov eax, [hook+0x2]
                mov dword[ebx], eax                                

                mov eax, [target]
                add eax, ecx
                mov [retCode+0x1], eax

                mov esi, shellcode
                mov edi, [hook+0x1]
                mov ecx, shellcode.size
                rep movsb
                call [target]
                ret

        hook:   push target
                ret
        hook.size = $ - hook

        shellcode:
                mov eax, 0
        origcode: rb 6
        origcode.size = $ - origcode
        retCode:
                mov eax, 0x0 
                add eax, hook.size
                jmp eax
        shellcode.size = $ - shellcode

        sizeOfFunction:
                push ecx
                
                xor ecx, ecx

        lp:     inc ecx
                mov eax, [esp+0x8]
                add eax, ecx
                mov eax, [eax]
                cmp ax, 0xCCCC
                jne lp

                mov eax, ecx
                pop ecx
                ret

section '.idata' import readable writeable
        library kernel, 'kernel32.dll'

        import kernel,\
                VirtualProtect, 'VirtualProtect',\
                VirtualAlloc, 'VirtualAlloc',\
                GetProcAddress, 'GetProcAddress'