
.CODE
	GetPeb PROC
		mov rax,gs:[60h]
		ret
	GetPeb ENDP

	JmpFunc PROC
		jmp rcx
	JmpFunc ENDP
	
 END