// InputInfo.cpp : 实现文件
//

#include "stdafx.h"
#include "Packer.h"
#include "InputInfo.h"
#include "afxdialogex.h"
#include "string"
#include "info.h"
// InputInfo 对话框

IMPLEMENT_DYNAMIC(InputInfo, CDialogEx)

InputInfo::InputInfo(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG2, pParent)
{

}

InputInfo::~InputInfo()
{
}

void InputInfo::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(InputInfo, CDialogEx)
	ON_BN_CLICKED(IDOK, &InputInfo::OnBnClickedOk)
END_MESSAGE_MAP()


// InputInfo 消息处理程序


void InputInfo::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	char buf[512];
	GetDlgItemTextA(IDC_PASSWORD,buf,512);
	gApplet.info.strPassword.clear();
	if (strlen(buf) > 15)
	{
		MessageBox("密码长度不能超过14位","提示",MB_ICONWARNING);
		return;
	}
	gApplet.info.strPassword = buf;
	OnOK();

}
