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
	char buf[512];
	GetDlgItemTextA(IDC_PASSWORD, buf, 512);
	gApplet.info.strPassword.clear();
	if (strlen(buf) > 15)
	{
		MessageBox("密码长度不能超过14位", "提示", MB_ICONWARNING);
		return;
	}
	if (gApplet.info.setTime)
		SetDate();
	if (gApplet.info.setPassword)
		gApplet.info.strPassword = buf;
	OnOK();

}

void InputInfo::SetDate()
{
	CDateTimeCtrl *tCdateTimeCtrlDate = (CDateTimeCtrl *)GetDlgItem(IDC_DATETIMEPICKER_DATE);
	CTime time;
	tCdateTimeCtrlDate->GetTime(time);
	gApplet.info.time.year = time.GetYear();
	gApplet.info.time.month = time.GetMonth();
	gApplet.info.time.day = time.GetDay();
	CDateTimeCtrl *tCdateTimeCtrlTime = (CDateTimeCtrl *)GetDlgItem(IDC_DATETIMEPICKER_TIME);
	tCdateTimeCtrlTime->GetTime(time);
	gApplet.info.time.hour = time.GetHour();
	gApplet.info.time.minute = time.GetMinute();
	gApplet.info.time.second = time.GetSecond();
}


BOOL InputInfo::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	if (!gApplet.info.setTime)
	{
		SetDisable(IDC_DATETIMEPICKER_DATE);
		SetDisable(IDC_DATETIMEPICKER_TIME);
	}
	if (!gApplet.info.setPassword)
	{
		SetDisable(IDC_PASSWORD);
	}

	// TODO:  在此添加额外的初始化

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

void InputInfo::SetDisable(DWORD dwId)
{
	GetDlgItem(dwId)->EnableWindow(FALSE);
}
