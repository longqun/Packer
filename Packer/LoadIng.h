#pragma once
#include "PictureEx.h"
#include "afxwin.h"

// LoadIng 对话框

class LoadIng : public CDialogEx
{
	DECLARE_DYNAMIC(LoadIng)

public:
	LoadIng( CWnd* pParent = NULL);   // 标准构造函数
	virtual ~LoadIng();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CPictureEx m_loadPic;
	bool m_isSetPassword;
	bool m_isSetTimeOut;
};
