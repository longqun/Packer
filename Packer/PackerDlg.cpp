
// PackerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Packer.h"
#include "PackerDlg.h"
#include "afxdialogex.h"
#include "util.h"
#include "vector"
#include "aplib.h"
#include "Task.h"
#include "info.h"
#include "Loading.h"
#pragma comment(lib, "aplib.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#pragma warning(disable: 4996)

extern HWND g_hwnd;
std::string path;
bool isPacking = false;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPackerDlg 对话框



CPackerDlg::CPackerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_PACKER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPackerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILENAME, m_FileName);
}

BEGIN_MESSAGE_MAP(CPackerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_TIMER()
	ON_MESSAGE(WM_UPDATE, &CPackerDlg::OnUpdateProgress)
	ON_MESSAGE(WM_UPDATEWRITEMEMORY, &CPackerDlg::OnUpdateWriteMemoryProgress)
	ON_BN_CLICKED(IDOK, &CPackerDlg::OnBnClickedOk)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON1, &CPackerDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CPackerDlg 消息处理程序
BOOL CPackerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标
	g_hwnd = GetSafeHwnd();
	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPackerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

LRESULT CPackerDlg::OnUpdateProgress(WPARAM wParam, LPARAM lParam)
{
	if (lParam != 0)
		m_progress.SetPos(((DWORD)wParam / (DWORD)lParam) * 100);
	return LRESULT();
}

LRESULT CPackerDlg::OnUpdateWriteMemoryProgress(WPARAM wParam, LPARAM lParam)
{
	if (lParam != 0)
		m_progress.SetPos(((DWORD)wParam / (DWORD)lParam) * 50);
	return LRESULT();
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPackerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CPackerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CPackerDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	if (path.empty())
	{
		MessageBoxA("路径不能为空","Packer",MB_ICONWARNING);
		return;
	}

	if (isPacking)
	{
		MessageBoxA("正在加壳中请等候", "Packer", MB_ICONWARNING);
		return;
	}
	LoadIng load;
	load.DoModal();
}


void CPackerDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	int DropCount = DragQueryFile(hDropInfo, -1, NULL, 0);//取得被拖动文件的数目  
	if (DropCount > 1)
	{
		MessageBox("目前只支持一个文件拖拽","提示",0);
		DragFinish(hDropInfo);
		return;
	}
	CHAR wsStr[MAX_PATH];
	DragQueryFileA(hDropInfo, 0, wsStr, MAX_PATH);
	std::string wsFileKind=wsStr;
	wsFileKind=wsFileKind.substr(wsFileKind.length()-3,3);
	if (stricmp(wsFileKind.c_str(),"exe")!=0)
	{
		MessageBox("只支持拖拽EXE文件","提示" , 0);
		DragFinish(hDropInfo);
		return;
	}
	DragFinish(hDropInfo);
	SetDlgItemTextA(IDC_FILENAME,wsStr);
	path = wsStr;
	CDialogEx::OnDropFiles(hDropInfo);
}


void CPackerDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	TCHAR szFilter[] = _T("可执行文件(*.exe)|*.exe|所有文件(*.*)|*.*||");
	CFileDialog fileDialog(TRUE,_T("exe"),NULL,0,szFilter,this);
	CString csFileName;
	if (IDOK == fileDialog.DoModal())
	{
		csFileName = fileDialog.GetPathName();
		std::string wsFileKind=csFileName.GetBuffer();
		wsFileKind=wsFileKind.substr(wsFileKind.length() - 3, 3);
		if (stricmp(wsFileKind.c_str(), "exe") != 0)
		{
			MessageBox("只支持EXE文件", "提示", 0);
			return;
		}
		SetDlgItemTextA(IDC_FILENAME, csFileName.GetBuffer());
		path = csFileName.GetBuffer();
	}
}
