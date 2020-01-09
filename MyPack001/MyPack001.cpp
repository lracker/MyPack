// MyPack001.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "CMyPack.h"

int main()
{
	char Path[256] = {};
	printf("请输入文件路径:");
	scanf_s("%s", Path, 256);
	// 保存新添加区段的名字
	CMyPack File((LPCSTR)".MyPack");
	// 读取被加壳程序
	File.LoadFile(Path);
	// 读取壳代码
	File.LoadStub((LPCSTR)"MyStub");
	// 保存TLS段的信息
//	File.SaveTLS();
	// 复制壳区段信息
	File.CopySectionInfo(".MyPack", ".text");
	// 复制dll的.reloc到这个程序新创建的.reloc里面
	File.CopySectionInfo(".nreloc", ".reloc");
	// 设置新的OEP
	File.SetOEP();
	// 设置导入表
	File.SetImport();
	// 加密区段
	File.EncrySection();
	// 保留旧的重定位表信息
	File.KeepReloc();
	// 复制壳段内容
	File.CopySectionContent(".MyPack", ".text");
	// 修复壳的重定位
	File.FixReloc();
	// 复制.reloc内容
	File.CopySectionContent(".nreloc", ".reloc");
	// 保存TLS
//	File.SetTLS();
	// 保存文件
	File.SaveFile((LPCSTR)"demo_2.exe");
}

