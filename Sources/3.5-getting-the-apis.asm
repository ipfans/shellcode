;Inputs:
;-------
;Esi --> Kernelbase
;Ebx -->The ArrayOfAPIs

GetAPIs Proc
 
 Local AddressFunctions:DWord
 Local AddressOfNameOrdinals:DWord
 Local AddressNames:DWord
 Local NumberOfNames:DWord
 Local ArrayOfAPIs:DWord

Getting_PE_Header:
 	Mov Edi, Esi								;Kernel32 imagebase
    Mov Eax, [Esi].IMAGE_DOS_HEADER.e_lfanew
    Add Esi, Eax								;Esi-->PE Header    Edi-->MZ Header
Getting_Export_Table:
 	Mov Eax, [Esi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress
 	Add Eax, Edi
 	Mov Esi, Eax
Getting_Arrays:
 	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
 	Add Eax, Edi
 	Mov AddressFunctions, Eax						;the first array
	
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
 	Add Eax, Edi
 	Mov AddressOfNameOrdinals, Eax						;the second array
  	
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames
 	Add Eax, Edi
 	Mov AddressNames, Eax							;the third array
	
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
 	Mov NumberOfNames, Eax								;the number of APIs
	
	Push Esi
 	Mov Esi, AddressNames
	Xor Ecx, Ecx
	
GetTheAPIs:
	Lodsd
	Push Esi
	Lea Esi, [Eax + Edi]		;RVA + imagebase = VA
	Xor Edx,Edx
	Xor Eax,Eax
Checksum_Calc:
    Lodsb
    Cmp Eax, 0
    Jz CheckFunction
    Add Edx,Eax
	Xor Edx,Eax
	Inc Edx
    Jmp Checksum_Calc
CheckFunction:
	Pop Esi
	Xor Eax, Eax				;The index of this API
	Cmp Edx, 0AAAAAAAAH			;FirstAPI
	Jz FoundAddress
	Cmp Edx, 0BBBBBBBBh			;SecondAPI
	Inc Eax
	Jz FoundAddress
	Cmp Edx, 0CCCCCCCCh			;ThirdAPI
	Inc Eax
	Jz FoundAddress
	Xor Eax, Eax
	Inc Ecx
	Cmp Ecx,NumberOfNames
	Jz EndFunc
	Jmp GetTheAPIs
FoundAddress:
	Mov Edx, Esi				;save it temporary in edx
	Pop Esi						;Esi --> PE Header
	Push Eax					;save the index of the API
	Mov Eax, AddressOfNameOrdinals
	Movzx Ecx, Word Ptr [Eax + Ecx * 2]
	Mov Eax, AddressFunctions
	Mov Eax, DWord Ptr [Eax + Ecx * 4]
	Add Eax, Edi
	Pop Ecx						;Get The Index of the API
	Mov [Ebx + Ecx * 4], Eax
	Push Esi
	Mov Esi, Edx
	Jmp GetTheAPIs
EndFunc:
	Mov Esi, Edi
 	Ret
GetAPIs EndP