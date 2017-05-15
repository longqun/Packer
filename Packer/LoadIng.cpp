// LoadIng.cpp : 实现文件
//

#include "stdafx.h"
#include "Packer.h"
#include "LoadIng.h"
#include "afxdialogex.h"
#include "Task.h"
#include "util.h"

LoadIng*currentDlg;
// LoadIng 对话框

IMPLEMENT_DYNAMIC(LoadIng, CDialogEx)

LoadIng::LoadIng(CWnd* pParent)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

LoadIng::~LoadIng()
{
	if (m_loadPic.IsPlaying())
		m_loadPic.Stop();
}


void LoadIng::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LOADINGPIC, m_loadPic);
}


BEGIN_MESSAGE_MAP(LoadIng, CDialogEx)
END_MESSAGE_MAP()


// LoadIng 消息处理程序


void ThreadFunc1(void *arglist)
{
	Task *task = new Task();
	replaceStringA(gApplet.filePath);
	gApplet.success = false;
	task->Start(gApplet.filePath.c_str());
	currentDlg->ShowWindow(SW_HIDE);
	if (gApplet.success)
		MessageBoxW(gApplet.loadingHwnd, L"加壳成功", L"Packer", 0);
	SendMessageA(gApplet.loadingHwnd, WM_CLOSE, 0, 0);
	gApplet.loadingHwnd = NULL;
	currentDlg = nullptr;
	delete task;
	_endthread();
}

BOOL LoadIng::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	currentDlg = this;
	// TODO:  在此添加额外的初始化
	gApplet.loadingHwnd = this->m_hWnd;
	if (m_loadPic.Load(MAKEINTRESOURCE(IDR_GIF1), _T("Gif")))
	{
		m_loadPic.CenterWindow();
		m_loadPic.Draw();
	}
	_beginthread(ThreadFunc1, NULL, NULL);
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
