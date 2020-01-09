#include "CMyPack.h"
#include <DbgHelp.h>
#include <stdio.h>
#include <time.h>
#include "lz4.h"
#pragma comment(lib, "DbgHelp.lib")

struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

CMyPack::CMyPack(LPCSTR SectionName)
{
	memcpy(m_SectionName, SectionName, strlen(SectionName) <= 8 ? strlen(SectionName) : 8);
}

//******************************************************************************
// 函数名称: GetDosHeader
// 函数说明: 获取到Dos头
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: DWORD PeBase
// 返 回 值: PIMAGE_DOS_HEADER
//******************************************************************************
PIMAGE_DOS_HEADER CMyPack::GetDosHeader(DWORD* PeBase)
{
	return (PIMAGE_DOS_HEADER)PeBase;
}

//******************************************************************************
// 函数名称: GetNtHeader
// 函数说明: 获取到NT头
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: DWORD PeBase
// 返 回 值: PIMAGE_NT_HEADERS
//******************************************************************************
PIMAGE_NT_HEADERS CMyPack::GetNtHeader(DWORD* PeBase)
{
	return (PIMAGE_NT_HEADERS)(GetDosHeader(PeBase)->e_lfanew + (DWORD)PeBase);
}

//******************************************************************************
// 函数名称: GetFileHeader
// 函数说明: 获取到文件头
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: DWORD PeBase
// 返 回 值: PIMAGE_FILE_HEADER
//******************************************************************************
PIMAGE_FILE_HEADER CMyPack::GetFileHeader(DWORD* PeBase)
{
	return (PIMAGE_FILE_HEADER)&GetNtHeader(PeBase)->FileHeader;
}

//******************************************************************************
// 函数名称: GetOpt
// 函数说明: 获取到区段头
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: DWORD PeBase
// 返 回 值: PIMAGE_OPTIONAL_HEADER
//******************************************************************************
PIMAGE_OPTIONAL_HEADER CMyPack::GetOptHeader(DWORD* PeBase)
{
	return (PIMAGE_OPTIONAL_HEADER)&GetNtHeader(PeBase)->OptionalHeader;
}

//******************************************************************************
// 函数名称: SetAlignment
// 函数说明: 用于按照指定字节进行对齐的函数
// 作    者: lracker
// 时    间: 2019/12/08
// 参    数: DWORD Num
// 参    数: DWORD Alignment
// 返 回 值: DWORD
//******************************************************************************
DWORD CMyPack::SetAlignment(DWORD Num, DWORD Alignment)
{
	return Num % Alignment == 0 ? Num : (Num / Alignment + 1) * Alignment;
}

//******************************************************************************
// 函数名称: GetSection
// 函数说明: 获取指定段的信息
// 作    者: lracker
// 时    间: 2019/12/08
// 参    数: DWORD * DllBase
// 参    数: LPCSTR SectionName
// 返 回 值: PIMAGE_SECTION_HEADER
//******************************************************************************
PIMAGE_SECTION_HEADER CMyPack::GetSection(DWORD* Base, LPCSTR SectionName)
{
	PIMAGE_SECTION_HEADER SectionTable = IMAGE_FIRST_SECTION(GetNtHeader(Base));
	for (int i = 0; i < GetFileHeader(Base)->NumberOfSections; ++i)
	{
		if (!memcmp(SectionTable[i].Name, SectionName, strlen(SectionName) + 1))
			return &SectionTable[i];
	}
	return nullptr;
}

//******************************************************************************
// 函数名称: LoadFile
// 函数说明: 打开文件并且加载文件到内存中
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: LPCTSTR FileName
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::LoadFile(LPCSTR FileName)
{
	// 获取到文件句柄
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	// 获取到文件的大小
	m_dwFileSize = GetFileSize(hFile, NULL);
	// 申请空间来存放文件的内容
	m_dwpFileBase = (DWORD*)malloc(m_dwFileSize * sizeof(BYTE));
	memset(m_dwpFileBase, 0, m_dwFileSize);
	// 获取实际读取的大小
	DWORD dwRead = 0;
	// 读取文件
	ReadFile(hFile, m_dwpFileBase, m_dwFileSize, &dwRead, NULL);
	// 防止句柄泄露，关闭句柄
	CloseHandle(hFile);
	// 压缩代码段
	char* NewPe = PackSection(".text", m_dwpFileBase);
	// 释放掉之前的空间
	free(m_dwpFileBase);
	m_dwpFileBase = (DWORD*)NewPe;
}

//******************************************************************************
// 函数名称: AddSection
// 函数说明: 为文件添加新的区段
// 作    者: lracker
// 时    间: 2019/12/07
// 参    数: LPCTSTR SectionName
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::CopySectionInfo(LPCSTR NewSectionName, LPCSTR SectionName)
{
	// 获取到最后一个区段的内容
	PIMAGE_SECTION_HEADER LastSection = &IMAGE_FIRST_SECTION(GetNtHeader(m_dwpFileBase))[GetFileHeader(m_dwpFileBase)->NumberOfSections - 1];
	// 添加新的区段表信息结构体
	// 文件头里的区段数量+1
	GetFileHeader(m_dwpFileBase)->NumberOfSections++;
	// 通过最后一个区段找到新的区段
	PIMAGE_SECTION_HEADER NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	// 从dll中找到我们要复制的新区段
	PIMAGE_SECTION_HEADER  SrcSection = GetSection(m_dwpDllBase, SectionName);
	// 从源区段中复制结构体信息到目标区段
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));
	// 设置区段的名称
	memcpy(NewSection->Name, NewSectionName, strlen(NewSectionName) <= 8 ? strlen(NewSectionName) : 8);
	// 设置区段的大小，分别为Misc.VirtualSize 和 SizeOfRawData
//	NewSection->Misc.VirtualSize = NewSection->SizeOfRawData = SrcSection->SizeOfRawData;
	// 设置区段的RVA = 上一个区段的RVA + 上一个区段对齐后的内存大小
	NewSection->VirtualAddress = LastSection->VirtualAddress + SetAlignment(LastSection->Misc.VirtualSize, GetOptHeader(m_dwpFileBase)->SectionAlignment);
	// 设置区段的FOA = 上一个区段的FOA + 上一个区段对齐后的内存大小
	NewSection->PointerToRawData = LastSection->PointerToRawData + SetAlignment(LastSection->SizeOfRawData, GetOptHeader(m_dwpFileBase)->FileAlignment);
	// 设置新的区段表中的数据: 区段属性
	NewSection->Characteristics = SrcSection->Characteristics;
	// 在PE文件中填充新的区段
	m_dwFileSize = NewSection->PointerToRawData + NewSection->SizeOfRawData;
	DWORD SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;
	// 重新申请一片内存空间，因为可以初始化为0.
	DWORD* TempBase = (DWORD*)malloc(m_dwFileSize * sizeof(BYTE));
	memset(TempBase, 0, m_dwFileSize);
	// NewSection->PointerToRawData其实之前的空间大小一样
	memcpy(TempBase, m_dwpFileBase, NewSection->PointerToRawData);
	free(m_dwpFileBase);
	m_dwpFileBase = TempBase;
	// 修改SizeOfImage的大小 
	GetOptHeader(m_dwpFileBase)->SizeOfImage = SizeOfImage;
}

//******************************************************************************
// 函数名称: CopySectionContent
// 函数说明: 复制区段内容
// 作    者: lracker
// 时    间: 2019/12/09
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::CopySectionContent(LPCSTR DestSectionName, LPCSTR SrcSectionName)
{
	// 复制段内内容
	BYTE* SrcData = (BYTE*)(GetSection(m_dwpDllBase, SrcSectionName)->VirtualAddress + (DWORD)m_dwpDllBase);
	BYTE* DstData = (BYTE*)(GetSection(m_dwpFileBase, DestSectionName)->PointerToRawData + (DWORD)m_dwpFileBase);
	memcpy(DstData, SrcData, GetSection(m_dwpDllBase, SrcSectionName)->SizeOfRawData);
}

//******************************************************************************
// 函数名称: SaveFile
// 函数说明: 保存到文件中
// 作    者: lracker
// 时    间: 2019/12/08
// 参    数: LPCTSTR FileName
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::SaveFile(LPCSTR FileName)
{
	// 获取创建文件的句柄
	HANDLE hFile = CreateFile(FileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	// 将内容写入文件中
	DWORD dwWrite = NULL;
	WriteFile(hFile, m_dwpFileBase, m_dwFileSize, &dwWrite, NULL);
	// 写完以后关闭句柄并且释放空间
	CloseHandle(hFile);
	free(m_dwpFileBase);
	m_dwpFileBase = NULL;
} 

//******************************************************************************
// 函数名称: LoadStub
// 函数说明: 读取壳代码dll到内存中
// 作    者: lracker
// 时    间: 2019/12/08
// 参    数: LPCSTR FileName
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::LoadStub(LPCSTR FileName)
{
	// 以执行DLL初始化的方式加载DLL
	m_dwpDllBase = (DWORD*)LoadLibraryExA(FileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// 从dll获取到start函数，并且计算出它的段内偏移
	DWORD Start = (DWORD)GetProcAddress((HMODULE)m_dwpDllBase, "start");
	m_dwStartOffset = Start - (DWORD)m_dwpDllBase - GetSection(m_dwpDllBase,".text")->VirtualAddress;
	m_pShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dwpDllBase, "ShareData");
	// 将数据填充到共享数据里
	m_pShareData->nSrcSize = m_nSrcSize;
	m_pShareData->nDestSize = m_nDestSize;
	m_pShareData->dwSectionRVA = m_dwSectionRVA;
}

//******************************************************************************
// 函数名称: SetOEP
// 函数说明: 设置OEP
// 作    者: lracker
// 时    间: 2019/12/09
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::SetOEP()
{
	// 保存旧的OEP的RVA
	m_pShareData->OldOep = GetOptHeader(m_dwpFileBase)->AddressOfEntryPoint;
	GetOptHeader(m_dwpFileBase)->AddressOfEntryPoint = GetSection(m_dwpFileBase, m_SectionName)->VirtualAddress + m_dwStartOffset;
}

//******************************************************************************
// 函数名称: FixReloc
// 函数说明: 修复壳代码的重定位
// 作    者: lracker
// 时    间: 2019/12/09
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::FixReloc()
{
	// 修复DLL里的.reloc内容，修复它里面的那些RVA为壳段.text的RVA
	PIMAGE_SECTION_HEADER pSection = GetSection(m_dwpFileBase, ".MyPack");
	DWORD dwSize = 0, dwOldProtect = 0;
	// 获取到程序的重定位表
	PIMAGE_BASE_RELOCATION pRelocTable = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData(m_dwpDllBase, TRUE, 5, &dwSize);
	while (pRelocTable->SizeOfBlock)
	{
		VirtualProtect((LPVOID)pRelocTable, 0x8, PAGE_READWRITE, &dwOldProtect);
		// 每一页的VirutalAddress都加上这个壳段的RVA
		pRelocTable->VirtualAddress += pSection->VirtualAddress - GetSection(m_dwpDllBase,".text")->VirtualAddress;
		VirtualProtect((LPVOID)pRelocTable, 0x8, dwOldProtect, &dwOldProtect);

		// 如果重定位的数据在代码段，就需要修改访问属性
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + (DWORD)m_dwpFileBase),
			0x1000, PAGE_READWRITE, &dwOldProtect);

		// 获取重定位项数组的首地址和重定位项的数量
		int count = (pRelocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(pRelocTable + 1);

		// 遍历每一个重定位项，输出内容
		for (int i = 0; i < count; ++i)
		{
			// 如果 type 的值为 3 我们才需要关注
			if (to[i].Type == 3)
			{
				DWORD Temp = RvaToFoa(m_dwpFileBase, pRelocTable->VirtualAddress);
				// 获取到需要重定位的地址所在的位置
				DWORD* addr = (DWORD*)((DWORD)m_dwpFileBase + Temp + to[i].Offset);
				DWORD Item = *addr - (DWORD)m_dwpDllBase - GetSection(m_dwpDllBase, ".text")->VirtualAddress;
				// 计算出不变的段内偏移 = *addr - imagebase - .text va
				*addr = Item + GetSection(m_dwpFileBase, ".MyPack")->VirtualAddress + 0x400000;
			}
		}

		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + (DWORD)m_dwpFileBase),
			0x1000, dwOldProtect, &dwOldProtect);
		// 找到下一个重定位块
		pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTable + pRelocTable->SizeOfBlock);
	}
	// 复制.reloc内容
	CopySectionContent(".nreloc", ".reloc");

}

//******************************************************************************
// 函数名称: EncrySection
// 函数说明: 加密区段
// 作    者: lracker
// 时    间: 2019/12/09
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::EncrySection()
{
	// 加密代码段
	PIMAGE_SECTION_HEADER pSection = GetSection(m_dwpFileBase, ".text");
	m_pShareData->dwRVA = pSection->VirtualAddress;
	m_pShareData->dwSize = pSection->SizeOfRawData;
	// pData指向代码段
	BYTE* pData = (BYTE*)(pSection->PointerToRawData + (DWORD)m_dwpFileBase);
	srand(time(NULL));
	// m_pShareData->bKey = rand() % 0xFF;
	m_pShareData->bKey = 0x11;
	for (int i = 0; i < pSection->SizeOfRawData; ++i)
		pData[i] ^= m_pShareData->bKey;
}

//******************************************************************************
// 函数名称: PackSection
// 函数说明: 压缩代码段
// 作    者: lracker
// 时    间: 2019/12/09
// 参    数: LPCSTR SectionName
// 返 回 值: VOID
//******************************************************************************
CHAR* CMyPack::PackSection(LPCSTR SectionName, DWORD* DllBase)
{
	// 找到这个text段
	PIMAGE_SECTION_HEADER pSection = GetSection(DllBase, SectionName);
	// 保存原来的大小
	int nSrcSize = pSection->SizeOfRawData;
	// 保存到共享数据里
	m_nSrcSize = nSrcSize;
	// 获取预估的压缩后的字节数(最坏的情况)：
	m_nCompressSize = LZ4_compressBound(nSrcSize);
	// 申请内存空间，用于保存压缩后的数据
	char* pBuffer = new char[m_nCompressSize]();
	// 开始压缩文件数据(函数返回压缩后的大小)
	int nDestSize = LZ4_compress((char*)(pSection->PointerToRawData + (DWORD)DllBase), pBuffer, pSection->SizeOfRawData);
	nDestSize = SetAlignment(nDestSize, GetOptHeader(DllBase)->FileAlignment);
	// 保存到共享数据里
	m_nDestSize = nDestSize;
	// 保存他的RVA
	m_dwSectionRVA = pSection->VirtualAddress;
	// 创建一个新的PE文件
	CHAR* NewPe = new CHAR[m_dwFileSize - nSrcSize + nDestSize]();
	int nSize1 = pSection->PointerToRawData;
	int nSize2 = pSection->PointerToRawData + pSection->SizeOfRawData;
	// 修改.text区段的大小
	pSection->SizeOfRawData = nDestSize;
	int nOffset = nSrcSize - nDestSize;
	// 后面的区段的FOA往前移动nOffset个字节
	ChangeSectionRVA(SectionName, nOffset, DllBase);
	// 修改文件总大小为压缩后的总大小
	GetOptHeader(DllBase)->SizeOfImage -= nOffset;
	// 复制.text区段之前的内容过去
	memcpy(NewPe, DllBase,nSize1);
	// 复制压缩后的text段
	memcpy(NewPe + nSize1, pBuffer, nDestSize);
	// 复制.text区段之后的内容过去
	memcpy(NewPe + nSize1 + nDestSize, (DWORD*)((DWORD)DllBase + nSize2), m_dwFileSize - nSize2);
	return NewPe;
}

//******************************************************************************
// 函数名称: RvaToFoa
// 函数说明: 用于RVA转FOA的
// 作    者: lracker
// 时    间: 2019/12/11
// 参    数: DWORD * PeBase
// 参    数: DWORD dwRVA
// 返 回 值: DWORD*
//******************************************************************************
DWORD CMyPack::RvaToFoa(DWORD* PeBase, DWORD dwRVA)
{
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(GetNtHeader(PeBase));
	for (int i = 0; i < GetFileHeader(PeBase)->NumberOfSections; ++i)
	{
		if ((dwRVA >= pSection[i].VirtualAddress) && (dwRVA < pSection[i].VirtualAddress + pSection[i].SizeOfRawData))
			return dwRVA - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
	}
}

//******************************************************************************
// 函数名称: ChangeSectionRVA
// 函数说明: 修改后面区段的RVA
// 作    者: lracker
// 时    间: 2019/12/10
// 参    数: LPCSTR SectionName
// 参    数: INT nOffset
// 参    数: DWORD * DllBase
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::ChangeSectionRVA(LPCSTR SectionName, INT nOffset, DWORD* DllBase)
{
	PIMAGE_SECTION_HEADER SectionTable = IMAGE_FIRST_SECTION(GetNtHeader(DllBase));
	int nIndex = 0;
	for (int i = 0; i < GetFileHeader(DllBase)->NumberOfSections; ++i)
	{
		if (!memcmp(SectionTable[i].Name, SectionName, strlen(SectionName) + 1))
		{
			nIndex = i + 1;
			break;
		}
	}
	// 该区段往后的FOA-nOffset
	for (int i = nIndex; i < GetFileHeader(DllBase)->NumberOfSections; ++i)
	{
		SectionTable[i].PointerToRawData -= nOffset;
	}
}

VOID CMyPack::KeepReloc()
{
	// 保留旧的数据目录表里重定位表的RVA
	m_pShareData->dwRelocRVA = GetOptHeader(m_dwpFileBase)->DataDirectory[5].VirtualAddress;
	// 修改文件的数据目录表为".nreloc"的RVA
	PIMAGE_SECTION_HEADER pReloc = GetSection(m_dwpFileBase, ".nreloc");
	GetOptHeader(m_dwpFileBase)->DataDirectory[5].VirtualAddress = pReloc->VirtualAddress;
	GetOptHeader(m_dwpFileBase)->DataDirectory[5].Size = GetOptHeader(m_dwpDllBase)->DataDirectory[5].Size;
	m_pShareData->dwFileImageBase = GetOptHeader(m_dwpFileBase)->ImageBase;
}

//******************************************************************************
// 函数名称: SetImport
// 函数说明: 清空数据目录表第[1]项和第[12]项数据
// 作    者: lracker
// 时    间: 2019/12/12
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::SetImport()
{
	// 保存原程序的导入表
	m_pShareData->dwOldImportRVA = GetOptHeader(m_dwpFileBase)->DataDirectory[1].VirtualAddress;
	// 清空导入表
	GetOptHeader(m_dwpFileBase)->DataDirectory[1].VirtualAddress = 0;
	GetOptHeader(m_dwpFileBase)->DataDirectory[1].Size = 0;
	// 清空IAT表
	GetOptHeader(m_dwpFileBase)->DataDirectory[12].VirtualAddress = 0;
	GetOptHeader(m_dwpFileBase)->DataDirectory[12].Size = 0;
	return;
}

//******************************************************************************
// 函数名称: SaveTLS
// 函数说明: 保存TLS段的信息
// 作    者: lracker
// 时    间: 2019/12/12
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::SaveTLS()
{
	// 假设TLS不存在
	if (GetOptHeader(m_dwpFileBase)->DataDirectory[9].VirtualAddress == 0)
	{
		m_pShareData->bTLSEnable = FALSE;
		return;
	}
	else
	{
		m_pShareData->bTLSEnable = TRUE;
		PIMAGE_TLS_DIRECTORY32 TlsDir = (PIMAGE_TLS_DIRECTORY32)(RvaToFoa(m_dwpFileBase, GetOptHeader(m_dwpFileBase)->DataDirectory[9].VirtualAddress) + (DWORD)m_dwpFileBase);
		// 获取到TlsIndex的Offset
		DWORD dwIndexFoa = RvaToFoa(m_dwpFileBase, TlsDir->AddressOfIndex - GetOptHeader(m_dwpFileBase)->ImageBase);
		m_pShareData->TlsIndex = 0;
		if (dwIndexFoa != -1)
			m_pShareData->TlsIndex = *(DWORD*)(dwIndexFoa + (DWORD)m_dwpFileBase);
		m_pShareData->pOldTls.StartAddressOfRawData = TlsDir->StartAddressOfRawData;
		m_pShareData->pOldTls.EndAddressOfRawData = TlsDir->EndAddressOfRawData;
		m_pShareData->pOldTls.AddressOfCallBacks = TlsDir->AddressOfCallBacks;
	}
}

//******************************************************************************
// 函数名称: SetTLS
// 函数说明: 设置TLS
// 作    者: lracker
// 时    间: 2019/12/12
// 返 回 值: VOID
//******************************************************************************
VOID CMyPack::SetTLS()
{
	if (m_pShareData->bTLSEnable == FALSE)
		return;
	// 将原程序的数据目标表第九项指向壳的数据目录表
	GetOptHeader(m_dwpFileBase)->DataDirectory[9].VirtualAddress = GetOptHeader(m_dwpDllBase)->DataDirectory[9].VirtualAddress - 0x1000 + GetSection(m_dwpFileBase, ".MyPack")->VirtualAddress;
	GetOptHeader(m_dwpFileBase)->DataDirectory[9].Size = GetOptHeader(m_dwpDllBase)->DataDirectory[9].Size;
	PIMAGE_TLS_DIRECTORY32 pTls = (PIMAGE_TLS_DIRECTORY32)(RvaToFoa(m_dwpFileBase, GetOptHeader(m_dwpFileBase)->DataDirectory[9].VirtualAddress) + (DWORD)m_dwpFileBase);
	DWORD IndexRva = (DWORD)&(m_pShareData->TlsIndex) - (DWORD)m_dwpDllBase - 0x1000 + GetSection(m_dwpFileBase, ".MyPack")->VirtualAddress;
	pTls->AddressOfIndex = IndexRva + GetOptHeader(m_dwpFileBase)->ImageBase;
	pTls->StartAddressOfRawData = m_pShareData->pOldTls.StartAddressOfRawData;
	pTls->EndAddressOfRawData = m_pShareData->pOldTls.EndAddressOfRawData;
	// 这里先取消TLS的回调函数，向共享结构体中传入TLS回调函数指针，在壳里手动调用TLS，并将TLS回调函数指针设置回去。
//	pTls->AddressOfCallBacks = 0;
}
