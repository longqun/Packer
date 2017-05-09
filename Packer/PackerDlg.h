
// PackerDlg.h : 头文件
//

#pragma once
#include "vector"
#include "info.h"
#include "afxcmn.h"
#include "afxwin.h"

// CPackerDlg 对话框
class CPackerDlg : public CDialogEx
{
// 构造
public:
	CPackerDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PACKER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg LRESULT OnUpdateProgress(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnUpdateWriteMemoryProgress(WPARAM wParam, LPARAM lParam);
	void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CProgressCtrl m_progress;
	afx_msg void OnBnClickedOk();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	CEdit m_FileName;

	afx_msg void OnBnClickedButton1();
};
