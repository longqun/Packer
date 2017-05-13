#pragma once


// InputInfo 对话框

class InputInfo : public CDialogEx
{
	DECLARE_DYNAMIC(InputInfo)

public:
	InputInfo(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~InputInfo();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG2 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	void SetDate();
	virtual BOOL OnInitDialog();
	void SetDisable(DWORD dwId);
};
