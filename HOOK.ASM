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
    call  NewKiUserExceptionDispatcher ;�Ⱦ��������Լ����쳣����

    ;mov rax,[OldKiUserExceptionDispatcher]  ;������ת��ȥ���쳣 ԭ��δ֪
    ;jmp rax 

    ;
    mov   rax, [OrgKiUserExceptionDispatcher] ;ֱ����ԭ����+ƫ�� ����RtlDispatchException ��������
    mov   rax,[rax]
    add   rax ,1ch
    jmp   rax; RtlDispatchException
    ret
MyKiUserExceptionDispatcher ENDP

END