#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <propidl.h>
#include <gdiplus.h>
#include <shellapi.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <dwmapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <cwchar>
#include <set>
#include <UIAutomation.h>
#include <oleauto.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "comctl32.lib")

using namespace Gdiplus;
static const wchar_t* APP_NAME=L"ScreenAudit";
static const UINT WM_TRAY=WM_APP+10, WM_FOREGROUND=WM_APP+11;
static const UINT ID_TRAY=1;
static HWND g_hwnd=nullptr;
static HWINEVENTHOOK g_hook=nullptr;
static ULONG_PTR g_gdiplus=0;
static bool g_tracking=true, g_dark=false, g_closing=false, g_startup=false;
static int g_page=0;
static std::set<std::wstring> g_ignoredApps;
static std::wstring g_currentUrl, g_currentContext=L"App activity";
static DWORD g_idleCutoff=5;
static ULONGLONG g_lastTick=0;
static std::wstring g_currentExe=L"Unknown", g_currentTitle=L"";
static std::map<std::wstring, ULONGLONG> g_usage;
static unsigned g_pickups=0;
static std::wstring g_dataDir, g_today;
static COLORREF C_BG, C_CARD, C_TEXT, C_MUTED, C_BORDER, C_BLUE=RGB(0,120,212);

static std::wstring Join(const std::wstring&a,const std::wstring&b){return a+L"\\"+b;}
static std::wstring DateKey(){
 SYSTEMTIME st; GetLocalTime(&st); wchar_t b[16]; swprintf(b,sizeof(b)/sizeof(b[0]),L"%04u-%02u-%02u",st.wYear,st.wMonth,st.wDay); return b;
}
static std::wstring AppDataDir(){
 wchar_t p[MAX_PATH]={}; DWORD n=GetEnvironmentVariableW(L"APPDATA",p,MAX_PATH);
 std::wstring d=(n&&n<MAX_PATH)?p:L".";
 d=Join(d,L"ScreenAudit"); CreateDirectoryW(d.c_str(),nullptr); return d;
}
static std::wstring Ini(const wchar_t* f){return Join(g_dataDir,f);}
static void LoadSettings(){
 g_idleCutoff=GetPrivateProfileIntW(L"Tracking",L"IdleCutoffMinutes",5,Ini(L"settings.ini").c_str());
 if(g_idleCutoff!=3&&g_idleCutoff!=5&&g_idleCutoff!=10)g_idleCutoff=5;
 g_tracking=GetPrivateProfileIntW(L"Tracking",L"Enabled",1,Ini(L"settings.ini").c_str())!=0;
 g_dark=GetPrivateProfileIntW(L"Appearance",L"Dark",0,Ini(L"settings.ini").c_str())!=0;
 g_startup=GetPrivateProfileIntW(L"Startup",L"Enabled",0,Ini(L"settings.ini").c_str())!=0;
 wchar_t ignored[8192]={}; GetPrivateProfileStringW(L"Privacy",L"IgnoredApps",L"",ignored,_countof(ignored),Ini(L"settings.ini").c_str());
 std::wstring raw=ignored; size_t pos=0;
 while(pos<raw.size()){size_t e=raw.find(L'|',pos);if(e==std::wstring::npos)e=raw.size();if(e>pos)g_ignoredApps.insert(raw.substr(pos,e-pos));pos=e+1;}
}
static void SaveSetting(const wchar_t* section,const wchar_t* key,DWORD v){
 wchar_t b[24]; swprintf(b,_countof(b),L"%lu",v); WritePrivateProfileStringW(section,key,b,Ini(L"settings.ini").c_str());
}
static std::wstring CsvEscape(const std::wstring&s){
 std::wstring o=L"\""; for(wchar_t c:s){if(c==L'"')o+=L"\"\"";else o+=c;} return o+L"\"";
}
static std::string ToUtf8(const std::wstring&s){
 if(s.empty())return {};
 int n=WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0,nullptr,nullptr);
 if(n<=0)return {};
 std::string out((size_t)n,'\0');
 WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),out.data(),n,nullptr,nullptr);
 return out;
}
static void AppendCsv(const std::wstring& exe,ULONGLONG ms){
 if(ms<1000)return;
 std::wstring path=Join(g_dataDir,g_today+L".csv");
 bool exists=GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES;
 std::ofstream f(std::filesystem::path(path),std::ios::binary|std::ios::app); if(!f)return;
 if(!exists)f<<"date,application,seconds\r\n";
 std::wstring row=CsvEscape(g_today)+L","+CsvEscape(exe)+L","+std::to_wstring(ms/1000)+L"\r\n";
 f<<ToUtf8(row);
}
static bool IsIdle(){
 LASTINPUTINFO li{}; li.cbSize=sizeof(li);
 if(!GetLastInputInfo(&li))return false;
 DWORD elapsed=GetTickCount()-li.dwTime;
 return elapsed>=g_idleCutoff*60*1000;
}
static std::wstring ProcessPath(DWORD pid){
 HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ,FALSE,pid);
 if(!h)return L"Unknown";
 wchar_t p[32768]={}; DWORD n=32768;
 BOOL ok=QueryFullProcessImageNameW(h,0,p,&n); CloseHandle(h);
 if(!ok)return L"Unknown";
 std::wstring s(p); size_t k=s.find_last_of(L"\\/"); return k==std::wstring::npos?s:s.substr(k+1);
}
struct ChildFind{DWORD framePid=0, childPid=0;};
static BOOL CALLBACK FindAppChild(HWND w,LPARAM lp){
 auto*x=reinterpret_cast<ChildFind*>(lp); DWORD pid=0; GetWindowThreadProcessId(w,&pid);
 if(pid && pid!=x->framePid && IsWindowVisible(w)){x->childPid=pid;return FALSE;} return TRUE;
}
static std::wstring ForegroundExe(){
 HWND w=GetForegroundWindow(); if(!w)return L"Unknown";
 DWORD pid=0; GetWindowThreadProcessId(w,&pid);
 if(ProcessPath(pid)==L"ApplicationFrameHost.exe"){
  ChildFind f; f.framePid=pid; EnumChildWindows(w,FindAppChild,reinterpret_cast<LPARAM>(&f));
  if(f.childPid)pid=f.childPid;
 }
 return ProcessPath(pid);
}
static std::wstring ForegroundTitle(){
 wchar_t b[512]={}; GetWindowTextW(GetForegroundWindow(),b,512); return b;
}
static void FlushCurrent(){
 ULONGLONG now=GetTickCount64();
 if(g_lastTick && g_tracking && !IsIdle() && g_currentExe!=L"Unknown" && !g_ignoredApps.count(g_currentExe)){
  ULONGLONG d=now-g_lastTick; g_usage[g_currentExe]+=d; AppendCsv(g_currentExe,d);
 }
 g_lastTick=now;
}
static bool IsBrowser(const std::wstring& exe){
 std::wstring e=exe;std::transform(e.begin(),e.end(),e.begin(),towlower);
 return e==L"chrome.exe"||e==L"msedge.exe"||e==L"brave.exe"||e==L"firefox.exe"||e==L"opera.exe"||e==L"vivaldi.exe";
}
static std::wstring ReadBrowserUrl(HWND hwnd){
 IUIAutomation* a=nullptr;IUIAutomationElement* root=nullptr;IUIAutomationCondition* cond=nullptr;IUIAutomationElementArray* arr=nullptr;
 std::wstring result;HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);bool uninit=SUCCEEDED(init);
 if(SUCCEEDED(CoCreateInstance(CLSID_CUIAutomation,nullptr,CLSCTX_INPROC_SERVER,IID_IUIAutomation,(void**)&a))&&SUCCEEDED(a->ElementFromHandle(hwnd,&root))){
  VARIANT v;VariantInit(&v);v.vt=VT_I4;v.lVal=UIA_EditControlTypeId;
  if(SUCCEEDED(a->CreatePropertyCondition(UIA_ControlTypePropertyId,v,&cond))&&SUCCEEDED(root->FindAll(TreeScope_Descendants,cond,&arr))){
   int n=0;arr->get_Length(&n);
   for(int i=0;i<n&&i<80;i++){
    IUIAutomationElement* el=nullptr;if(FAILED(arr->GetElement(i,&el))||!el)continue;
    IUIAutomationValuePattern* vp=nullptr;
    if(SUCCEEDED(el->GetCurrentPatternAs(UIA_ValuePatternId,IID_IUIAutomationValuePattern,(void**)&vp))&&vp){
     BSTR b=nullptr;if(SUCCEEDED(vp->get_CurrentValue(&b))&&b){
      std::wstring candidate(b,SysStringLen(b));SysFreeString(b);
      if(candidate.rfind(L"https://",0)==0||candidate.rfind(L"http://",0)==0){result=candidate;vp->Release();el->Release();break;}
     }vp->Release();
    }el->Release();
   }
  }
 }
 if(arr)arr->Release();if(cond)cond->Release();if(root)root->Release();if(a)a->Release();if(uninit)CoUninitialize();return result;
}
static std::wstring ContextFromUrl(const std::wstring& url){
 std::wstring u=url;std::transform(u.begin(),u.end(),u.begin(),towlower);
 if(u.find(L"pw.live")!=std::wstring::npos||u.find(L"physicswallah")!=std::wstring::npos)return L"Physics Wallah • verified URL";
 if(u.find(L"youtube.com")!=std::wstring::npos||u.find(L"youtu.be")!=std::wstring::npos)return L"YouTube • verified URL";
 if(u.find(L"instagram.com")!=std::wstring::npos)return L"Instagram • verified URL";
 if(u.find(L"chatgpt.com")!=std::wstring::npos||u.find(L"chat.openai.com")!=std::wstring::npos)return L"ChatGPT • verified URL";
 if(u.find(L"gemini.google.com")!=std::wstring::npos)return L"Google Gemini • verified URL";
 if(u.find(L"claude.ai")!=std::wstring::npos)return L"Claude • verified URL";
 if(u.find(L"perplexity.ai")!=std::wstring::npos)return L"Perplexity • verified URL";
 return L"Browser • URL detected";
}
static void SaveIgnored(){
 std::wstring raw;for(const auto& x:g_ignoredApps){if(!raw.empty())raw+=L"|";raw+=x;}
 WritePrivateProfileStringW(L"Privacy",L"IgnoredApps",raw.c_str(),Ini(L"settings.ini").c_str());
}
static void SaveStartup(bool enabled){
 HKEY k;if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE,&k)==ERROR_SUCCESS){
  if(enabled){wchar_t p[MAX_PATH]={};GetModuleFileNameW(nullptr,p,MAX_PATH);std::wstring cmd=L"\""+std::wstring(p)+L"\"";RegSetValueExW(k,L"ScreenAudit",0,REG_SZ,(BYTE*)cmd.c_str(),(DWORD)((cmd.size()+1)*sizeof(wchar_t)));}
  else RegDeleteValueW(k,L"ScreenAudit");RegCloseKey(k);
 }
 g_startup=enabled;SaveSetting(L"Startup",L"Enabled",enabled?1:0);
}
static void OnForeground(){
 FlushCurrent();HWND w=GetForegroundWindow();g_currentExe=ForegroundExe();g_currentTitle=ForegroundTitle();
 g_currentUrl.clear();g_currentContext=L"App activity";
 if(IsBrowser(g_currentExe)){g_currentUrl=ReadBrowserUrl(w);g_currentContext=g_currentUrl.empty()?L"Browser • URL not available":ContextFromUrl(g_currentUrl);}
 InvalidateRect(g_hwnd,nullptr,FALSE);
}
static void CALLBACK WinEventProc(HWINEVENTHOOK,DWORD,HWND,LONG,LONG,DWORD,DWORD){
 if(g_hwnd)PostMessageW(g_hwnd,WM_FOREGROUND,0,0);
}
static void RefreshColors(){
 if(g_dark){C_BG=RGB(32,32,32);C_CARD=RGB(43,43,43);C_TEXT=RGB(245,245,245);C_MUTED=RGB(170,170,170);C_BORDER=RGB(56,56,56);}
 else{C_BG=RGB(243,243,243);C_CARD=RGB(255,255,255);C_TEXT=RGB(32,32,32);C_MUTED=RGB(100,100,100);C_BORDER=RGB(229,229,229);}
}
static std::wstring FormatTime(ULONGLONG ms){
 ULONGLONG m=ms/60000; wchar_t b[64];
 if(m>=60)swprintf(b,_countof(b),L"%lluh %llum",m/60,m%60);else swprintf(b,_countof(b),L"%llum",m);
 return b;
}
static ULONGLONG TodayTotal(){ULONGLONG n=0;for(auto&x:g_usage)n+=x.second;return n;}
static void LoadToday(){
 g_usage.clear(); g_today=DateKey();
 std::wstring p=Join(g_dataDir,g_today+L".csv"); std::wifstream f{std::filesystem::path(p)}; if(!f)return;
 std::wstring line; std::getline(f,line);
 while(std::getline(f,line)){
  size_t a=line.find(L",\""); if(a==std::wstring::npos)continue;
  size_t b=line.find(L"\",",a+2); if(b==std::wstring::npos)continue;
  size_t c=line.find_last_of(L','); if(c==std::wstring::npos)continue;
  std::wstring exe=line.substr(a+2,b-a-2); ULONGLONG sec=_wtoi64(line.substr(c+1).c_str());
  g_usage[exe]+=sec*1000;
 }
}
static void DrawText(Graphics&g,const std::wstring&s,REAL x,REAL y,REAL size,Color c,bool bold=false){
 FontFamily ff(L"Segoe UI"); Font f(&ff,size,bold?FontStyleBold:FontStyleRegular,UnitPixel);
 SolidBrush br(c); g.DrawString(s.c_str(),(INT)s.size(),&f,PointF(x,y),&br);
}
static void Card(Graphics&g,REAL x,REAL y,REAL w,REAL h){
 SolidBrush b(Color(255,GetRValue(C_CARD),GetGValue(C_CARD),GetBValue(C_CARD)));
 Pen p(Color(255,GetRValue(C_BORDER),GetGValue(C_BORDER),GetBValue(C_BORDER)),1);
 g.FillRectangle(&b,x,y,w,h);g.DrawRectangle(&p,x,y,w,h);
}
static void Paint(HWND hwnd){
 PAINTSTRUCT ps; HDC hdc=BeginPaint(hwnd,&ps); RECT rc;GetClientRect(hwnd,&rc);
 int w=rc.right,h=rc.bottom;
 Bitmap bmp(w,h); Graphics g(&bmp);g.SetSmoothingMode(SmoothingModeAntiAlias);
 g.Clear(Color(255,GetRValue(C_BG),GetGValue(C_BG),GetBValue(C_BG)));
 DrawText(g,L"ScreenAudit",24,18,25,Color(255,GetRValue(C_TEXT),GetGValue(C_TEXT),GetBValue(C_TEXT)),true);
 DrawText(g,L"Screen time and activity",25,50,12,Color(255,GetRValue(C_MUTED),GetGValue(C_MUTED),GetBValue(C_MUTED)));
 Pen blue(Color(255,0,120,212),3);g.DrawLine(&blue,24,78,142,78);
 REAL top=98, gap=14, cw=(w-64-gap*2)/3;
 Card(g,24,top,cw,104);Card(g,24+cw+gap,top,cw,104);Card(g,24+2*(cw+gap),top,cw,104);
 auto tc=Color(255,GetRValue(C_TEXT),GetGValue(C_TEXT),GetBValue(C_TEXT));
 auto mc=Color(255,GetRValue(C_MUTED),GetGValue(C_MUTED),GetBValue(C_MUTED));
 DrawText(g,L"TODAY'S SCREEN TIME",40,112,10,mc,true);
 DrawText(g,FormatTime(TodayTotal()),40,138,27,tc,true);
 DrawText(g,L"TRACKED APPS",40+cw+gap,112,10,mc,true);
 DrawText(g,std::to_wstring(g_usage.size()),40+cw+gap,138,27,tc,true);
 DrawText(g,L"CURRENT APP",40+2*(cw+gap),112,10,mc,true);
 DrawText(g,g_currentExe,40+2*(cw+gap),140,17,tc,true);
 Card(g,24,top+120,w-48,h-top-145);
 DrawText(g,L"App usage today",42,top+137,17,tc,true);
 std::vector<std::pair<std::wstring,ULONGLONG>> rows(g_usage.begin(),g_usage.end());
 std::sort(rows.begin(),rows.end(),[](auto&a,auto&b){return a.second>b.second;});
 REAL y=top+174; int shown=0; ULONGLONG maxv=rows.empty()?1:rows.front().second;
 for(auto&r:rows){if(shown++>=10)break;
  DrawText(g,r.first,42,y,13,tc);DrawText(g,FormatTime(r.second),w-125,y,12,mc);
  SolidBrush track(Color(255,GetRValue(C_BORDER),GetGValue(C_BORDER),GetBValue(C_BORDER)));
  SolidBrush fill(Color(255,0,120,212));g.FillRectangle(&track,(REAL)42,y+(REAL)23,(REAL)(w-170),(REAL)5);
  g.FillRectangle(&fill,(REAL)42,y+(REAL)23,(REAL)(w-170)*(REAL)r.second/(REAL)maxv,(REAL)5); y+=42;
 }
 if(rows.empty())DrawText(g,L"Usage will appear here as you switch between apps.",42,y,13,mc);
 DrawText(g,g_tracking?L"Tracking: On":L"Tracking: Paused",24,h-18,11,mc);
 Graphics target(hdc);target.DrawImage(&bmp,0,0);
 EndPaint(hwnd,&ps);
}
static void ExportCsv(){
 OPENFILENAMEW o{}; wchar_t path[MAX_PATH]=L"ScreenAudit-usage.csv";
 o.lStructSize=sizeof(o);o.hwndOwner=g_hwnd;o.lpstrFilter=L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
 o.lpstrFile=path;o.nMaxFile=MAX_PATH;o.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;o.lpstrDefExt=L"csv";
 if(!GetSaveFileNameW(&o))return;
 std::ofstream out(path,std::ios::binary);if(!out)return;out<<"date,application,seconds\r\n";
 WIN32_FIND_DATAW fd;HANDLE f=FindFirstFileW(Join(g_dataDir,L"????-??-??.csv").c_str(),&fd);
 if(f!=INVALID_HANDLE_VALUE){do{
  std::ifstream in(std::filesystem::path(Join(g_dataDir,fd.cFileName)),std::ios::binary);
  std::string line;bool header=true;
  while(std::getline(in,line)){if(header){header=false;continue;}out<<line<<"\r\n";}
 }while(FindNextFileW(f,&fd));FindClose(f);}
}
static void SetStartup(bool enabled){
 HKEY k; if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE,&k)!=ERROR_SUCCESS)return;
 if(enabled){wchar_t p[MAX_PATH];GetModuleFileNameW(nullptr,p,MAX_PATH);std::wstring command=L"\""+std::wstring(p)+L"\"";RegSetValueExW(k,L"ScreenAudit",0,REG_SZ,(BYTE*)command.c_str(),(DWORD)((command.size()+1)*sizeof(wchar_t)));}
 else RegDeleteValueW(k,L"ScreenAudit");RegCloseKey(k);
}
static void TrayMenu(){
 HMENU m=CreatePopupMenu();
 AppendMenuW(m,MF_STRING,100,L"Open ScreenAudit");
 AppendMenuW(m,MF_STRING,101,g_tracking?L"Pause Tracking":L"Resume Tracking");
 AppendMenuW(m,MF_STRING,102,L"Export CSV Report");
 AppendMenuW(m,MF_STRING,103,L"Start with Windows (Toggle)");
 AppendMenuW(m,MF_SEPARATOR,0,nullptr);
 AppendMenuW(m,MF_STRING|MF_CHECKED*(g_dark?1:0),105,L"Dark mode");
 AppendMenuW(m,MF_SEPARATOR,0,nullptr);
 AppendMenuW(m,MF_STRING|MF_CHECKED*(g_idleCutoff==3?1:0),106,L"Idle cutoff: 3 minutes");
 AppendMenuW(m,MF_STRING|MF_CHECKED*(g_idleCutoff==5?1:0),107,L"Idle cutoff: 5 minutes");
 AppendMenuW(m,MF_STRING|MF_CHECKED*(g_idleCutoff==10?1:0),108,L"Idle cutoff: 10 minutes");
 AppendMenuW(m,MF_SEPARATOR,0,nullptr);AppendMenuW(m,MF_STRING,104,L"Exit");
 POINT p;GetCursorPos(&p);SetForegroundWindow(g_hwnd);
 int c=TrackPopupMenu(m,TPM_RETURNCMD|TPM_NONOTIFY,p.x,p.y,0,g_hwnd,nullptr);DestroyMenu(m);
 if(c==100)ShowWindow(g_hwnd,SW_SHOW);
 if(c==101){FlushCurrent();g_tracking=!g_tracking;SaveSetting(L"Tracking",L"Enabled",g_tracking);g_lastTick=GetTickCount64();InvalidateRect(g_hwnd,nullptr,TRUE);}
 if(c==102)ExportCsv();
 if(c==103){HKEY k;bool on=false;if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&k)==ERROR_SUCCESS){on=RegQueryValueExW(k,L"ScreenAudit",0,nullptr,nullptr,nullptr)==ERROR_SUCCESS;RegCloseKey(k);}SetStartup(!on);}
 if(c==105){g_dark=!g_dark;SaveSetting(L"Appearance",L"Dark",g_dark?1:0);RefreshColors();BOOL dark=g_dark?TRUE:FALSE;DwmSetWindowAttribute(g_hwnd,20,&dark,sizeof(dark));InvalidateRect(g_hwnd,nullptr,TRUE);}
 if(c==106||c==107||c==108){g_idleCutoff=c==106?3:(c==107?5:10);SaveSetting(L"Tracking",L"IdleCutoffMinutes",g_idleCutoff);}
 if(c==104){g_closing=true;DestroyWindow(g_hwnd);}
}
static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM wp,LPARAM lp){
 switch(m){
 case WM_CREATE:{
  g_hwnd=h;NOTIFYICONDATAW n{};n.cbSize=sizeof(n);n.hWnd=h;n.uID=ID_TRAY;n.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;n.uCallbackMessage=WM_TRAY;
  n.hIcon=LoadIconW(nullptr,IDI_APPLICATION);lstrcpynW(n.szTip,L"ScreenAudit",(int)(sizeof(n.szTip)/sizeof(n.szTip[0])));Shell_NotifyIconW(NIM_ADD,&n);
  WTSRegisterSessionNotification(h,NOTIFY_FOR_THIS_SESSION);
  g_hook=SetWinEventHook(EVENT_SYSTEM_FOREGROUND,EVENT_SYSTEM_FOREGROUND,nullptr,WinEventProc,0,0,WINEVENT_OUTOFCONTEXT|WINEVENT_SKIPOWNPROCESS);
  SetTimer(h,1,15000,nullptr);g_lastTick=GetTickCount64();OnForeground();return 0;}
 case WM_FOREGROUND:OnForeground();return 0;
 case WM_TIMER:{
  if(DateKey()!=g_today){FlushCurrent();LoadToday();}
  FlushCurrent();
  LASTINPUTINFO li{};li.cbSize=sizeof(li);if(GetLastInputInfo(&li)){static DWORD last=0;if(li.dwTime!=last){last=li.dwTime;}}
  InvalidateRect(h,nullptr,FALSE);return 0;}
 case WM_WTSSESSION_CHANGE:if(wp==WTS_SESSION_UNLOCK)++g_pickups;return 0;
 case WM_TRAY:if(lp==WM_RBUTTONUP||lp==WM_CONTEXTMENU)TrayMenu();else if(lp==WM_LBUTTONUP)ShowWindow(h,SW_SHOW);return 0;
 case WM_SYSCOMMAND:if((wp&0xFFF0)==SC_CLOSE){ShowWindow(h,SW_HIDE);return 0;}break;
 case WM_ERASEBKGND:return 1;
 case WM_PAINT:Paint(h);return 0;
 case WM_DESTROY:{
  FlushCurrent();KillTimer(h,1);if(g_hook)UnhookWinEvent(g_hook);
  WTSUnRegisterSessionNotification(h);NOTIFYICONDATAW n{};n.cbSize=sizeof(n);n.hWnd=h;n.uID=ID_TRAY;Shell_NotifyIconW(NIM_DELETE,&n);
  PostQuitMessage(0);return 0;}
 }
 return DefWindowProcW(h,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE, PWSTR,int){
 g_dataDir=AppDataDir();LoadSettings();RefreshColors();LoadToday();
 GdiplusStartupInput gi;GdiplusStartup(&g_gdiplus,&gi,nullptr);
 INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_STANDARD_CLASSES};InitCommonControlsEx(&ic);
 WNDCLASSEXW wc{sizeof(wc)};wc.lpfnWndProc=WndProc;wc.hInstance=inst;wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION);wc.hbrBackground=nullptr;wc.lpszClassName=L"ScreenAuditWindow";
 if(!RegisterClassExW(&wc))return 1;
 DWORD ex=WS_EX_APPWINDOW;HWND h=CreateWindowExW(ex,wc.lpszClassName,APP_NAME,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,900,650,nullptr,nullptr,inst,nullptr);
 if(!h)return 2;g_hwnd=h;
 BOOL dark=g_dark?TRUE:FALSE;DwmSetWindowAttribute(h,20,&dark,sizeof(dark));
 ShowWindow(h,SW_SHOW);UpdateWindow(h);
 MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 GdiplusShutdown(g_gdiplus);return 0;
}
