// Hook_KiUserExceptionDispatcher.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "afxwin.h" 
#include <iostream>


LONG __stdcall VCHandler(
    EXCEPTION_POINTERS* ExceptionInfo
) {

    printf("VCH 异常将被忽略 发生地址:%p RAX:0x%016I64x RCX:0x%016I64x RDX:0x%016I64x R8:0x%016I64x  R9:0x%016I64x\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9);
    return EXCEPTION_CONTINUE_EXECUTION;//忽略异常=什么都没发生 try块当然也无法捕获到 
}
LONG __stdcall VEHandler(
    EXCEPTION_POINTERS* ExceptionInfo
)
{
    printf("VEH 异常将被忽略 发生地址:%p RAX:0x%016I64x RCX:0x%016I64x RDX:0x%016I64x R8:0x%016I64x  R9:0x%016I64x\n", ExceptionInfo->ContextRecord->Rip, ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx, ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9);
     
    return EXCEPTION_CONTINUE_EXECUTION;//忽略异常=什么都没发生 try块当然也无法捕获到
}
LONG   __stdcall   SEHandler(_EXCEPTION_POINTERS* excp)
{
    printf("SEH 异常将被忽略 发生地址:%p RAX:0x%016I64x RCX:0x%016I64x RDX:0x%016I64x R8:0x%016I64x  R9:0x%016I64x\n", excp->ExceptionRecord->ExceptionAddress, excp->ContextRecord->Rax, excp->ContextRecord->Rcx, excp->ContextRecord->Rdx, excp->ContextRecord->R8, excp->ContextRecord->R9);

    return  EXCEPTION_CONTINUE_EXECUTION;//忽略异常=什么都没发生 try块当然也无法捕获到
}
//以上是正常的异常监视 


VOID StackTrace64(PCONTEXT  Context)
{

    KNONVOLATILE_CONTEXT_POINTERS NvContext;
    UNWIND_HISTORY_TABLE          UnwindHistoryTable;
    PRUNTIME_FUNCTION             RuntimeFunction;
    PVOID                         HandlerData;
    ULONG64                       EstablisherFrame;
    ULONG64                       ImageBase;
     
    RtlZeroMemory(
        &UnwindHistoryTable,
        sizeof(UNWIND_HISTORY_TABLE));

    RuntimeFunction = RtlLookupFunctionEntry(
        Context->Rip,
        &ImageBase,
        &UnwindHistoryTable
    );

    RtlZeroMemory(
        &NvContext,
        sizeof(KNONVOLATILE_CONTEXT_POINTERS));

    if (!RuntimeFunction)
    { 
        Context->Rip = (ULONG64)(*(PULONG64)Context->Rsp);
        Context->Rsp += 8;
    }
    else
    { 
        RtlVirtualUnwind(
            UNW_FLAG_EHANDLER,
            ImageBase,
            Context->Rip,
            RuntimeFunction,
            Context,
            &HandlerData,
            &EstablisherFrame,
            &NvContext);  
    }


    return;
}


extern "C" void   NewKiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT  Context)
{ 
	
    if (ExceptionRecord->ExceptionCode == 1010)//确认我们自己的异常 可以用线程ID替代？
    { 
        printf("劫持异常代码 ： %d\n此次异常不会执行任务异常处理程序\n", ExceptionRecord->ExceptionCode); 
        //利用栈回溯 获取异常函数call下一条指令地址？  
        StackTrace64(Context);
    	//+0x2  是__except处理的的地址
        Context->Rip += 0x2;
        //通知R0 从__except开始运行 
        RtlRestoreContext(Context, 0);  
    	//下边不会运行
        printf("这句永远不会运行\n"); 
    }
}
//函数定义
typedef VOID(WINAPI* PtrKiUserExceptionDispatcher)();
extern "C" VOID MyKiUserExceptionDispatcher();//汇编函数

extern "C"   PtrKiUserExceptionDispatcher OldKiUserExceptionDispatcher = nullptr;
extern "C"  PtrKiUserExceptionDispatcher OrgKiUserExceptionDispatcher = nullptr;//原函数
 

#include "MinHook.h"
#pragma comment(lib, "libMinHook")
void func(int cc) {
    
    __try
    {
        printf("__try start,%p\n", func);
        RaiseException(
            cc,                    // exception code 
            0,                    
            0, NULL);     
    }
    __except (1)
    {
        printf("__except start\n");

    }  
    printf("func ok\n");  
}
int main()
{
    SetUnhandledExceptionFilter(SEHandler);//正常的监视全局异常
    AddVectoredContinueHandler(1, VCHandler);//正常的监视全局异常
    AddVectoredExceptionHandler(1, VEHandler);//正常的监视全局异常
    HMODULE ntapp=GetModuleHandleA("ntdll.dll"); 
    OrgKiUserExceptionDispatcher = (PtrKiUserExceptionDispatcher)GetProcAddress(ntapp, ("KiUserExceptionDispatcher"));
    if (MH_Initialize() == MH_OK)
    {
        if (MH_OK == MH_CreateHook(OrgKiUserExceptionDispatcher, MyKiUserExceptionDispatcher, reinterpret_cast<void**>(&OldKiUserExceptionDispatcher)))
        {
            if (MH_OK == MH_EnableHook(OrgKiUserExceptionDispatcher))
            {
                printf("钩子安装成功!\n");
            }
        }
    }
    printf("********************\n");
    printf("本次异常已被劫持\n");
    func(1010);
    printf("********************\n");
    printf("本次会进入全局异常\n");
    func(1);
    printf("********************\n");
	std::cout << "最后来一句传统的!\nHello World!\n";
}

