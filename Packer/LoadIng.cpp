// LoadIng.cpp : 实现文件
//

#include "stdafx.h"
#include "Packer.h"
#include "LoadIng.h"
#include "afxdialogex.h"
#include "Task.h"
#include "util.h"

extern HWND g_hwnd;
extern std::string path;
extern bool isPacking;
LoadIng*currentDlg;
// LoadIng 对话框

IMPLEMENT_DYNAMIC(LoadIng, CDialogEx)

LoadIng::LoadIng(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

LoadIng::~LoadIng()
{
	if (m_loadPic.IsPlaying())
		m_loadPic.Stop();
	g_hwnd = NULL;
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
	Task *task = new Task(g_hwnd);
	replaceStringA(path);
	task->Init(path.c_str());
	currentDlg->ShowWindow(SW_HIDE);
	MessageBoxW(g_hwnd, L"加壳成功", L"Packer", 0);
	SendMessageA(g_hwnd, WM_CLOSE, 0, 0);
	g_hwnd = NULL;
	currentDlg = nullptr;
	delete task;
	isPacking = false;
	_endthread();
}

BOOL LoadIng::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	currentDlg = this;
	// TODO:  在此添加额外的初始化
	g_hwnd = this->m_hWnd;
	if (m_loadPic.Load(MAKEINTRESOURCE(IDR_GIF1), _T("Gif")))
	{
		m_loadPic.CenterWindow();
		m_loadPic.Draw();
	}
	_beginthread(ThreadFunc1, NULL, NULL);
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
