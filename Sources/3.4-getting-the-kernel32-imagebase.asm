.Data
DB 0
.Code
mov eax,dword ptr fs:[30]
mov eax,dword ptr [eax+C]
mov ebx,dword ptr [eax+1C]
mov ebx,dword ptr [ebx]
mov esi,dword ptr [ebx+8]

