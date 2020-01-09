#include <windows.h>

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

class CMyPack
{
private:
	// 保存了PE文件的加载基址
	DWORD* m_dwpFileBase;
	// 保存了DLL文件的加载基址
	DWORD* m_dwpDllBase;
	// 保存文件的大小
	DWORD m_dwFileSize;
	// start的段内偏移
	DWORD m_dwStartOffset;
	// 保存共享信息
	PSHAREDATA m_pShareData = nullptr;
	// 保存段名
	CHAR m_SectionName[8] = {};
	// 保存压缩后的大小
	INT m_nCompressSize;
	// 保存压缩段的FOA
	DWORD m_dwSectionRVA = 0;
	// 保存压缩段压缩后大小
	INT m_nDestSize = 0;
	// 保存压缩段原始大小
	INT m_nSrcSize = 0;
private:
	// 获取到DOS头
	PIMAGE_DOS_HEADER GetDosHeader(DWORD* PeBase);
	// 获取到NT头
	PIMAGE_NT_HEADERS GetNtHeader(DWORD* PeBase);
	// 获取到文件头
	PIMAGE_FILE_HEADER GetFileHeader(DWORD* PeBase);
	// 获取到拓展头
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD* PeBase);
	// 用于按照指定字节进行对齐的函数
	DWORD SetAlignment(DWORD Num, DWORD Alignment);
	// 获取段信息
	PIMAGE_SECTION_HEADER GetSection(DWORD* DllBase, LPCSTR);
	// 压缩代码段
	CHAR* PackSection(LPCSTR SectionName, DWORD* DllBase);
	// RVA转FOA
	DWORD RvaToFoa(DWORD* PeBase, DWORD dwRVA);
public:
	// 保存段名
	CMyPack(LPCSTR SectionName);
	// 打开文件并且加载文件到内存中
	VOID LoadFile(LPCSTR FileName);
	// 为文件添加新的区段
	VOID CopySectionInfo(LPCSTR NewSectionName, LPCSTR SectionName);
	// 复制区段内容
	VOID CopySectionContent(LPCSTR DestSectionName, LPCSTR SrcSectionName);
	// 保存到文件中
	VOID SaveFile(LPCSTR FileName);
	// 读取壳代码dll到内存中
	VOID LoadStub(LPCSTR FileName);
	// 设置OEP
	VOID SetOEP();
	// 修复壳代码的重定位
	VOID FixReloc();
	// 加密区段
	VOID EncrySection();
	// 修改后面区段的FOA
	VOID ChangeSectionRVA(LPCSTR SectionName, INT nOffset, DWORD* DllBase);
	// 保留旧的重定位表信息
	VOID KeepReloc();
	// 清空保存数据目录表第[1]和[12]项的数据
	VOID SetImport();
	// 保存TLS段信息
	VOID SaveTLS();
	// 设置TLS
	VOID SetTLS();
};

