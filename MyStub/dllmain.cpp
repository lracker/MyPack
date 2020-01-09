// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "lz4.h"
#include <DbgHelp.h>
#include <winternl.h>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

DWORD GetFunAddr(DWORD* DllBase, char* FunName);
#define DefApiFun(name)\
	decltype(name)* My_##name = NULL;
#define DefineFuncPtr(base, name)\
		My_##name = (decltype(name)*)GetFunAddr(base, (char*)#name)

typedef HANDLE(CALLBACK* HHeapCreate)(_In_ DWORD flOptions, _In_ SIZE_T dwInitialSize, _In_ SIZE_T dwMaximumSize);
typedef LPVOID(CALLBACK* LPHeapAlloc)(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
typedef BOOL(CALLBACK* BHeapFree)(_Inout_ HANDLE hHeap, _In_ DWORD dwFlags, __drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem);

DefApiFun(GetProcAddress);
DefApiFun(VirtualProtect);
DefApiFun(LoadLibraryA);
DefApiFun(GetMessageA);
DefApiFun(TranslateMessage);
DefApiFun(DispatchMessageA);
DefApiFun(RegisterClassExA);
DefApiFun(CreateWindowExA);
DefApiFun(ShowWindow);
DefApiFun(UpdateWindow);
DefApiFun(GetModuleHandleA);
DefApiFun(DefWindowProcA);
DefApiFun(GetWindowTextA);
DefApiFun(PostQuitMessage);
DefApiFun(GetStockObject);
DefApiFun(MessageBoxA);
DefApiFun(VirtualAlloc);
DefApiFun(GetCurrentProcess);
DefApiFun(ExitProcess);


//定义函数NtQueryInformationProcess的指针类型
typedef  NTSTATUS(NTAPI* PNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

PNtQueryInformationProcess pNtQueryInformationProcess;

// 使得产生TLS表
_declspec(thread) int g_num;

struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

typedef struct _SHAREDATA
{
	// 原始OEP
	LONG OldOep = 0;
	// 区段的大小
	DWORD dwSize = 0;
	// 区段的RVA
	DWORD dwRVA = 0;
	// 密钥
	BYTE bKey = 0;
	// 原始数据大小
	INT nSrcSize = 0;
	// 压缩后数据大小
	INT nDestSize = 0;
	// 压缩数据的FOA
	DWORD dwSectionRVA = 0;
	// 保留文件重定位表的RVA
	DWORD dwRelocRVA = 0;
	// 保留文件的ImageBase
	DWORD dwFileImageBase = 0;
	// 保留原程序导入表的RVA
	DWORD dwOldImportRVA = 0;
	// TLS是否存在
	BOOL bTLSEnable = TRUE;
	// Index一般为0
	DWORD TlsIndex = 0;
	// 保存TLS表的信息
	IMAGE_TLS_DIRECTORY pOldTls;
}SHAREDATA, * PSHAREDATA;

DWORD GetFunAddr(DWORD* DllBase, char* FunName)
{
	// 遍历导出表
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DllBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)pDos);
	PIMAGE_OPTIONAL_HEADER pOt = (PIMAGE_OPTIONAL_HEADER)&pNt->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pOt->DataDirectory[0].VirtualAddress + (DWORD)DllBase);
	// 获取到ENT、EOT、EAT
	DWORD* pENT = (DWORD*)(pExport->AddressOfNames + (DWORD)DllBase);
	WORD* pEOT = (WORD*)(pExport->AddressOfNameOrdinals + (DWORD)DllBase);
	DWORD* pEAT = (DWORD*)(pExport->AddressOfFunctions + (DWORD)DllBase);
	for (int i = 0; i < pExport->NumberOfNames; ++i)
	{
		char* Name = (char*)(pENT[i] + (DWORD)DllBase);
		if (!strcmp(Name, FunName))
			return pEAT[pEOT[i]] + (DWORD)DllBase;
	}
	return -1;
}

extern "C"
{
	
	__declspec(naked) DWORD* GetKernel32()
	{
		__asm
		{
			mov eax, fs: [0x30] ;
			mov eax, [eax + 0xC];
			mov eax, [eax + 0x1C];
			mov eax, [eax];
			mov eax, [eax];
			mov eax, [eax + 8];
			ret;
		}
	}

	__declspec(dllexport) SHAREDATA ShareData;

	//******************************************************************************
	// 函数名称: GetImageBase
	// 函数说明: 获取到加载基址
	// 作    者: lracker
	// 时    间: 2019/12/09
	// 返 回 值: void
	//******************************************************************************
	__declspec(naked) DWORD GetImageBase()
	{
		__asm
		{
			mov eax, fs: [0x30] ;
			mov eax, [eax + 0x8];
			ret;
		}
	}

	VOID GetApi()
	{
		DWORD* KernelBase = GetKernel32();
		DefineFuncPtr(KernelBase, GetProcAddress);
		DefineFuncPtr(KernelBase, VirtualProtect);
		DefineFuncPtr(KernelBase, VirtualAlloc);
		DefineFuncPtr(KernelBase, GetModuleHandleA);
		DefineFuncPtr(KernelBase, LoadLibraryA);
		DefineFuncPtr(KernelBase, GetCurrentProcess);
		DefineFuncPtr(KernelBase, ExitProcess);

		HMODULE hUser32 = My_LoadLibraryA("user32.dll");
		DefineFuncPtr((DWORD*)hUser32, CreateWindowExA);
		DefineFuncPtr((DWORD*)hUser32, GetMessageA);
		DefineFuncPtr((DWORD*)hUser32, RegisterClassExA);
		DefineFuncPtr((DWORD*)hUser32, TranslateMessage);
		DefineFuncPtr((DWORD*)hUser32, DispatchMessageA);
		DefineFuncPtr((DWORD*)hUser32, ShowWindow);
		DefineFuncPtr((DWORD*)hUser32, UpdateWindow);
		DefineFuncPtr((DWORD*)hUser32, GetWindowTextA);
		DefineFuncPtr((DWORD*)hUser32, PostQuitMessage);
		DefineFuncPtr((DWORD*)hUser32, DefWindowProcA);
		DefineFuncPtr((DWORD*)hUser32, MessageBoxA);

		HMODULE hNtdll = My_LoadLibraryA("Ntdll.dll");
		pNtQueryInformationProcess = (PNtQueryInformationProcess)My_GetProcAddress(hNtdll, "NtQueryInformationProcess");
		HMODULE hGDI = My_LoadLibraryA("Gdi32.dll");
		DefineFuncPtr((DWORD*)hGDI, GetStockObject);
	}

	//******************************************************************************
	// 函数名称: Decry
	// 函数说明: 解密我们的代码段
	// 作    者: lracker
	// 时    间: 2019/12/09
	// 返 回 值: void
	//******************************************************************************
	void Decry()
	{
		// 修改属性
		DWORD dwOldProtect = 0;
		My_VirtualProtect((LPVOID)(ShareData.dwRVA + GetImageBase()), ShareData.dwSize, PAGE_READWRITE, &dwOldProtect);
		BYTE* Data = (BYTE*)(ShareData.dwRVA + GetImageBase());
		for (int i = 0; i < ShareData.dwSize; ++i)
			Data[i] ^= ShareData.bKey;
		My_VirtualProtect((LPVOID)(ShareData.dwRVA + GetImageBase()), ShareData.dwSize, dwOldProtect, &dwOldProtect);
	}

	//******************************************************************************
	// 函数名称: JmpOEP
	// 函数说明: 跳回到原始的OEP
	// 作    者: lracker
	// 时    间: 2019/12/09
	// 返 回 值: void
	//******************************************************************************
	__declspec(naked) void JmpOEP()
	{
		__asm
		{
			mov eax, fs: [0x30] ;
			mov eax, [eax + 0x8];
			mov ebx, ShareData.OldOep;
			add ebx, eax;
			jmp ebx;
			__emit(0xE8);
		}
	}

	//******************************************************************************
	// 函数名称: WndProc
	// 函数说明: 弹窗的回调函数
	// 作    者: lracker
	// 时    间: 2019/12/12
	// 参    数: HWND hWnd
	// 参    数: UINT uMsg
	// 参    数: WPARAM wParam
	// 参    数: LPARAM lParam
	// 返 回 值: LRESULT CALLBACK
	//******************************************************************************
	LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{	// 保存编辑框句柄
		static HWND EditHwnd = 0;	
		switch (uMsg)
		{
			case WM_CREATE:
			{
				EditHwnd = My_CreateWindowExA(0, "edit", NULL, WS_CHILD | WS_BORDER | WS_VISIBLE, 20, 20, 150, 20, hWnd, (HMENU)0x1000, (HINSTANCE)GetImageBase(), NULL);
				My_CreateWindowExA(0, "button", "确定", WS_CHILD | WS_VISIBLE, 50, 70, 100, 20, hWnd, (HMENU)0x1001, (HINSTANCE)GetImageBase(), NULL);
				break;
			}
			case WM_COMMAND:
			{
				if (wParam == 0x1001)
				{
					char  Buff[100] = {};
					My_GetWindowTextA(EditHwnd, Buff, 100);
					if (!strcmp(Buff, "hello"))
					{
						My_PostQuitMessage(0);
						My_ShowWindow(hWnd, SW_HIDE);
						break;
					}
				}
				break;
			}
		}
		return My_DefWindowProcA(hWnd, uMsg, wParam, lParam);
	}

	//******************************************************************************
	// 函数名称: Enter
	// 函数说明: 弹出窗口看看是否进入主程序
	// 作    者: lracker
	// 时    间: 2019/12/09
	// 返 回 值: BOOL
	//******************************************************************************
	VOID Enter()
	{
		// 创建窗口类
		WNDCLASSEXA WndClass = { sizeof(WndClass) };
		WndClass.style = CS_HREDRAW | CS_VREDRAW;
		WndClass.hInstance = (HINSTANCE)GetImageBase();
		WndClass.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);
		WndClass.lpszClassName = "MyWindow";
		WndClass.lpfnWndProc = WndProc;
		// 注册窗口类
		My_RegisterClassExA(&WndClass);
		HWND hWnd = My_CreateWindowExA(0, "MyWindow", "Hello", WS_OVERLAPPEDWINDOW,
			100, 100, 250, 250, NULL, NULL,
			(HINSTANCE)GetImageBase(), NULL);
		// 显示更新
		My_ShowWindow(hWnd, SW_SHOW);
		My_UpdateWindow(hWnd);
		// 消息循环
		MSG msg = {};  //消息
		while (My_GetMessageA(&msg, 0, 0, 0))
		{
			// 转换消息 分发消息
			My_TranslateMessage(&msg);
			My_DispatchMessageA(&msg);
		}
	}

	//******************************************************************************
	// 函数名称: UnPackSection
	// 函数说明: 解压代码段
	// 作    者: lracker
	// 时    间: 2019/12/10
	// 参    数: LPCSTR SectionName
	// 参    数: DWORD * DllBase
	// 返 回 值: CHAR*
	//******************************************************************************
	VOID UnPackSection(LPCSTR SectionName, DWORD* DllBase) 
	{
		// 修改属性
		DWORD dwOldProtect = 0;
		My_VirtualProtect((LPVOID)(ShareData.dwRVA + (DWORD)DllBase), ShareData.nSrcSize, PAGE_READWRITE, &dwOldProtect);
		CHAR* Data = (CHAR*)(ShareData.dwSectionRVA + (DWORD)DllBase);
		// 申请空间
		HHeapCreate HeapCreate = (HHeapCreate)My_GetProcAddress((HMODULE)GetKernel32(), "HeapCreate");
		HANDLE hHeap = HeapCreate(0, 0, 0);
		LPHeapAlloc lpHeapAlloc = (LPHeapAlloc)My_GetProcAddress((HMODULE)GetKernel32(), "HeapAlloc");
		CHAR* pBuff = (CHAR*)lpHeapAlloc(hHeap, HEAP_ZERO_MEMORY, ShareData.nSrcSize);
		// 解压
		LZ4_uncompress_unknownOutputSize(Data, pBuff, ShareData.nDestSize, ShareData.nSrcSize);
		memcpy(Data, pBuff, ShareData.nSrcSize);
		My_VirtualProtect((LPVOID)(ShareData.dwRVA + (DWORD)DllBase), ShareData.nSrcSize, dwOldProtect, &dwOldProtect);
		// 释放掉空间
		BHeapFree bHeapFree = (BHeapFree)My_GetProcAddress((HMODULE)GetKernel32(), "HeapFree");
		bHeapFree(hHeap, 0, pBuff);
	}

	//******************************************************************************
	// 函数名称: FixIAT
	// 函数说明: 修复IAT表
	// 作    者: lracker
	// 时    间: 2019/12/12
	// 返 回 值: VOID
	//******************************************************************************
	//00FE12B2 | 50 | push eax |
	//00FE12B3 | 58 | pop eax | push eip; jmp xxxxxxxxx
	//00FE12B4 | 60 | pushad |
	//00FE12B5 | 61 | popad |
	//00FE12B6 | B8 11111111 | mov eax, 11111111 |
	//00FE12BB | FFE0 | jmp eax |
	VOID FixIAT()
	{
		char ShellCode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ShareData.dwOldImportRVA + (DWORD)GetImageBase());
		// 遍历导入表
		while (pImport->Name)
		{
			char* DllName = (char*)(pImport->Name + (DWORD)GetImageBase());
			// 加载当前DLL
			HMODULE MoDule = My_LoadLibraryA(DllName);
			DWORD* pInt = (DWORD*)(pImport->OriginalFirstThunk + (DWORD)GetImageBase());
			DWORD* pIat = (DWORD*)(pImport->FirstThunk + (DWORD)GetImageBase());
			while (*pInt)
			{
				// 保存真正的函数地址
				LPVOID Fun;
				// 导入的函数是序号还是名称
				if (*pInt & 0x80000000)
				{
					DWORD Order = (*pIat) & 0xFFFF;
					Fun = My_GetProcAddress(MoDule, (char*)Order);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME FunName = (PIMAGE_IMPORT_BY_NAME)(*pInt + (DWORD)GetImageBase());
					Fun = My_GetProcAddress(MoDule, (char*)FunName->Name);
				}
				// 申请空间
				char* pBuff = (char*)My_VirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				// 拷贝shellcode
				memcpy(pBuff, ShellCode, sizeof(ShellCode));
				// 写入真正的函数
				*(DWORD*)&pBuff[5] = (DWORD)Fun;
				// 修改IAT表中的函数地址，需要权限
				DWORD dwOld = 0;
				My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &dwOld);
				// 填充IAT
				*pIat = (DWORD)pBuff;
				My_VirtualProtect(pIat, 4, dwOld, &dwOld);
				pInt++;
				pIat++;
			}
			pImport++;
		}
	}

	//******************************************************************************
	// 函数名称: FixFileReloc
	// 函数说明: 修复文件内的重定位
	// 作    者: lracker
	// 时    间: 2019/12/11
	// 返 回 值: VOID
	//******************************************************************************
	VOID FixFileReloc()
	{
		DWORD dwBase = GetImageBase();
		DWORD dwSize = 0, dwOldProtect = 0;
		// 获取到程序的重定位表
		PIMAGE_BASE_RELOCATION RelocTable = (PIMAGE_BASE_RELOCATION)(ShareData.dwRelocRVA + dwBase);
		// 如果SizeOfBlock不为空，则说明存在重定位块
		while (RelocTable->SizeOfBlock)
		{
			// 如果重定位的数据在代码段，就需要修改访问属性
			My_VirtualProtect((LPVOID)(RelocTable->VirtualAddress + dwBase), 0x2000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			int nCount = (RelocTable->SizeOfBlock - 8) / 2;
			TypeOffset* to = (TypeOffset*)(RelocTable + 1);
			for (int i = 0; i < nCount; ++i)
			{
				// 如果type的值为3，则需要重定位
				if (to[i].Type == 3)
				{
					// 获取到需要重定位的地址所在的位置
					DWORD* addr = (DWORD*)(dwBase + RelocTable->VirtualAddress + to[i].Offset);
					// 计算重定位后的地址
					*addr = *addr - ShareData.dwFileImageBase + dwBase;
				}
			}
			// 还原区段的保护属性
		//	My_VirtualProtect((LPVOID)(RelocTable->VirtualAddress + dwBase), 0x2000, dwOldProtect, &dwOldProtect);
			// 找到下一个重定位块
			RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)RelocTable + RelocTable->SizeOfBlock);
		}
	}

	//******************************************************************************
	// 函数名称: SetTls
	// 函数说明: 设置TLS
	// 作    者: lracker
	// 时    间: 2019/12/12
	// 返 回 值: VOID
	//******************************************************************************
	VOID SetTls()
	{
		DWORD dwBase = GetImageBase();
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + dwBase);
		PIMAGE_OPTIONAL_HEADER32 pOpt = (PIMAGE_OPTIONAL_HEADER32)&pNt->OptionalHeader;
		if (ShareData.bTLSEnable == TRUE)
		{
			// 将TLS回调函数指针设置回去
			DWORD dwRVA = pOpt->DataDirectory[9].VirtualAddress;
			PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(dwRVA + dwBase);
			pTlsDir->AddressOfCallBacks = ShareData.pOldTls.AddressOfCallBacks;
			PIMAGE_TLS_CALLBACK* lpTlsFun = (PIMAGE_TLS_CALLBACK*)(ShareData.pOldTls.AddressOfCallBacks - ShareData.dwFileImageBase + dwBase);
			while ((*lpTlsFun) != NULL)
			{
				(*lpTlsFun)((PVOID)dwBase, DLL_THREAD_ATTACH, NULL);
				lpTlsFun++;
			}
		}
	}

	// 下面是虚拟机壳的
	// push 0x12345678 push一个4字节的数
	#define vPushData 0x10
	// call 0x12345678 call一个4字节的地址
	#define vCall 0x12
	// 结束符
	#define vEnd 0xff
	char* str = (char*)"这是虚拟机";
	/*
		这是我们构造的虚拟指令
		push 0
		push offset str
		push offset str
		push 0
		call MessageBoxA
	*/
	BYTE g_bVmData[] = {
		vPushData,0x00,0x00,0x00,0x00,
		vPushData,0x00,0x00,0x00,0x00,
		vPushData,0x00,0x00,0x00,0x00,
		vPushData,0x00,0x00,0x00,0x00,
		vCall,0x00,0x00,0x00,0x00,
		vEnd
	};
	// 简单的虚拟引擎
	_declspec(naked) void VM(PVOID pvmData)
	{
		__asm
		{
			push ebp;
			mov ebp, esp;
			sub esp, 0x64;
			// 取vCode地址放入ecx
			mov ecx, dword ptr ss : [ebp + 8] ;
		__vStart:
			// 取第一个字节到al中
			mov al, byte ptr ds : [ecx] ;
			cmp al, vPushData;
			je __vPushData;
			cmp al, vCall;
			je __vCall;
			cmp al, vEnd;
			je __vEnd;
			int 3;
		__vPushData:
			inc ecx;
			mov edx, dword ptr ds : [ecx] ;
			push edx;
			add ecx, 4;
			jmp __vStart;
		__vCall:
			inc ecx;
			mov edx, dword ptr ds : [ecx] ;
			//保存ecx的值
			mov dword ptr ds : [ebp + 0x10] , ecx
			call edx;
			//返回ecx的值
			mov ecx, dword ptr ds : [ebp + 0x10]
			add ecx, 4;
			jmp __vstart;
		__vEnd:
			//平衡堆栈
			add esp, 0x64
				pop ebp
			ret;
		}
	}
	VOID VMStart()
	{
		//修改虚拟指令的数据

		*(DWORD*)(g_bVmData + 5 + 1) = (DWORD)str;
		*(DWORD*)(g_bVmData + 10 + 1) = (DWORD)str;
		*(DWORD*)(g_bVmData + 20 + 1) = (DWORD)My_MessageBoxA;

		//执行虚拟指令
		VM(g_bVmData);
	}

	//******************************************************************************
	// 函数名称: CheckProcessDebugPort
	// 函数说明: 检查端口是否被调试了
	// 作    者: lracker 
	// 时    间: 2019/12/13
	// 返 回 值: BOOL
	//******************************************************************************
	BOOL CheckProcessDebugPort()
	{
		int nDebugPort = 0;
		pNtQueryInformationProcess(My_GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugPort, &nDebugPort, sizeof(nDebugPort), NULL);
		return nDebugPort == 0xFFFFFFFF ? true : false;
	}

	//******************************************************************************
	// 函数名称: AntiDebug
	// 函数说明: 反调试
	// 作    者: lracker
	// 时    间: 2019/12/13
	// 返 回 值: VOID
	//******************************************************************************
	VOID AntiDebug()
	{
		if (CheckProcessDebugPort())
		{
			My_MessageBoxA(0, "正在被调试", 0, 0);
			My_ExitProcess(0);
		}

	}
	__declspec(dllexport) __declspec(naked) void start()
	{
		g_num;
		__asm
		{
			xor eax, eax;
			TEST eax, eax;
			jz _Start;
			jnz _Start;
			__emit(0xE8);

		_Start:
			xor eax, 3;
			add eax, 4;
			xor eax, 5;
		}
		
		// 获取需要的API
		GetApi();
		// 虚拟机的代码
		VMStart();
		// 反调试
	//	AntiDebug();
		// 弹窗
		Enter();
		// 解密咱们的代码段
		Decry();
		// 解压代码
		UnPackSection(".text", (DWORD*)GetImageBase());
		// 修复文件的重定位
		FixFileReloc();
		// 修复IAT
		FixIAT();
		// 设置TLS
//		SetTls();
		// 跳回到原始OEP 
		JmpOEP();
	}
}