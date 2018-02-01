#ifndef SSDTINFO_H
#define SSDTINFO_H

#include <ntddk.h>

//保存KiSystemCall64的msr寄存器的名字
#define MSR_LSTAR 0xC0000082

//win7-*64 NtCreateDebugObject在SSDT中的下标
#define Index_NtCreateDebugObject 144

extern UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

extern unsigned __int64 __readmsr(int register);				//读取msr寄存器

extern unsigned __int64 __readcr0(void);			//读取cr0的值

extern void __writecr0(unsigned __int64 Data);		//写入cr0

extern void __debugbreak();							//断点，类似int 3

extern void __disable(void);						//屏蔽中断

extern void __enable(void);							//允许中断

//SSDT表的结构
typedef struct _SYSTEM_SERVICE_TABLE
{
	PUINT32 ServiceTableBase;
	PUINT32 ServiceCounterTableBase;
	UINT64 NumberOfServices;
	PUCHAR ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
#endif