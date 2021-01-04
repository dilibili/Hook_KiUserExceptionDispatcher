extrn NewKiUserExceptionDispatcher : proc 
extrn OrgKiUserExceptionDispatcher : proc  
extrn OldKiUserExceptionDispatcher : proc 
.data
.code


;hook 
public MyKiUserExceptionDispatcher

MyKiUserExceptionDispatcher PROC  
    mov   rcx, rsp 
    add  rcx,4F0h
    mov   rdx,rsp  
    call  NewKiUserExceptionDispatcher ;先经过我们自己的异常处理

    ;mov rax,[OldKiUserExceptionDispatcher]  ;这样跳转回去会异常 原因未知
    ;jmp rax 

    ;
    mov   rax, [OrgKiUserExceptionDispatcher] ;直接用原函数+偏移 跳到RtlDispatchException 这样可以
    mov   rax,[rax]
    add   rax ,1ch
    jmp   rax; RtlDispatchException
    ret
MyKiUserExceptionDispatcher ENDP

END