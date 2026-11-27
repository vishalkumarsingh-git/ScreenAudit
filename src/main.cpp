#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
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
#include <cwctype>
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
 size_t scheme=url.find(L"://");if(scheme==std::wstring::npos)return L"Browser • URL not available";
 size_t begin=scheme+3,end=url.find_first_of(L"/?#:",begin);std::wstring host=url.substr(begin,end==std::wstring::npos?std::wstring::npos:end-begin);
 std::transform(host.begin(),host.end(),host.begin(),towlower);
 auto domain=[&](const wchar_t* d){size_t n=wcslen(d);return host==d||(host.size()>n&&host.compare(host.size()-n,n,d)==0&&host[host.size()-n-1]==L'.');};
 if(domain(L"pw.live")||domain(L"physicswallah.com"))return L"Physics Wallah • verified URL";
 if(domain(L"youtube.com")||domain(L"youtu.be"))return L"YouTube • verified URL";
 if(domain(L"instagram.com"))return L"Instagram • verified URL";
 if(domain(L"chatgpt.com")||host==L"chat.openai.com")return L"ChatGPT • verified URL";
 if(domain(L"gemini.google.com"))return L"Google Gemini • verified URL";
 if(domain(L"claude.ai"))return L"Claude • verified URL";
 if(domain(L"perplexity.ai"))return L"Perplexity • verified URL";
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
 PAINTSTRUCT ps;HDC hdc=BeginPaint(hwnd,&ps);RECT rc;GetClientRect(hwnd,&rc);int w=rc.right,h=rc.bottom;
 Bitmap bmp(w,h);Graphics g(&bmp);g.SetSmoothingMode(SmoothingModeAntiAlias);
 auto col=[](COLORREF c){return Color(255,GetRValue(c),GetGValue(c),GetBValue(c));};
 auto tc=col(C_TEXT),mc=col(C_MUTED),blue=Color(255,0,120,212);
 g.Clear(col(C_BG));SolidBrush side(Color(255,255,255));g.FillRectangle(&side,0,0,220,h);
 Pen div(Color(255,226,226,230),1);g.DrawLine(&div,219,0,219,h);
 DrawText(g,L"◉  ScreenAudit",18,18,18,Color(255,28,28,32),true);
 DrawText(g,L"LOCAL ACTIVITY",19,53,9,Color(255,135,135,145),true);
 const wchar_t* nav[]={L"◉   Screen Time",L"▥   Reports",L"⊘   Do Not Monitor",L"⚙   Settings"};
 for(int i=0;i<4;i++){REAL y=92+i*48;if(g_page==i){SolidBrush active(Color(255,232,241,255));g.FillRectangle(&active,8,y,202,40);}DrawText(g,nav[i],20,y+10,13,g_page==i?blue:Color(255,42,42,48),g_page==i);}
 DrawText(g,L"FREE • ALL FEATURES",18,h-30,9,Color(255,110,110,120),true);
 const wchar_t* labels[]={L"Screen Time",L"Usage reports",L"Excluded applications",L"Settings"};
 DrawText(g,labels[g_page],244,38,25,tc,true);
 DrawText(g,g_page==0?L"WINDOWS DESKTOP":g_page==1?L"ACTIVITY HISTORY":g_page==2?L"PRIVACY CONTROLS":L"PREFERENCES",244,18,9,mc,true);
 SolidBrush btn(Color(255,255,255));Pen bp(Color(255,215,215,222),1);g.FillRectangle(&btn,w-112,16,92,34);g.DrawRectangle(&bp,w-112,16,92,34);
 DrawText(g,g_tracking?L"Ⅱ  Pause":L"▶  Resume",w-100,26,11,tc,true);
 std::vector<std::pair<std::wstring,ULONGLONG>> rows(g_usage.begin(),g_usage.end());
 std::sort(rows.begin(),rows.end(),[](auto&a,auto&b){return a.second>b.second;});
 if(g_page==0){
  Card(g,240,92,w-264,132);DrawText(g,L"ACTIVE TODAY",262,112,10,mc,true);DrawText(g,FormatTime(TodayTotal()),260,136,34,tc,true);
  DrawText(g,L"Tracked applications  "+std::to_wstring(g_usage.size()),262,188,11,mc);
  Card(g,240,242,w-264,86);DrawText(g,L"CURRENT ACTIVITY",260,258,10,mc,true);
  DrawText(g,g_currentExe+L"   •   "+g_currentContext,260,281,14,tc,true);
  Card(g,240,346,w-264,h-366);DrawText(g,L"MOST USED",260,365,11,mc,true);
  REAL y=396;ULONGLONG maxv=rows.empty()?1:rows.front().second;
  for(size_t i=0;i<rows.size()&&i<10&&y<h-35;i++){DrawText(g,rows[i].first,262,y,13,tc,true);DrawText(g,FormatTime(rows[i].second),w-145,y,12,mc);SolidBrush track(Color(255,235,237,241)),fill(blue);g.FillRectangle(&track,262,y+22,w-410,5);g.FillRectangle(&fill,262,y+22,(REAL)(w-410)*(REAL)rows[i].second/(REAL)maxv,5);y+=42;}
  if(rows.empty())DrawText(g,L"Your app usage will appear here as you use Windows.",262,405,13,mc);
 }else if(g_page==1){
  Card(g,240,92,w-264,h-116);DrawText(g,L"APPLICATION USAGE • TODAY",262,112,11,mc,true);REAL y=150;
  for(auto&r:rows){if(y>h-55)break;DrawText(g,r.first,262,y,13,tc,true);DrawText(g,FormatTime(r.second),w-145,y,12,mc);y+=34;}
  if(rows.empty())DrawText(g,L"No activity recorded yet.",262,155,13,mc);
 }else if(g_page==2){
  Card(g,240,92,w-264,h-116);DrawText(g,L"Select apps to exclude from future tracking. Existing history is retained.",262,112,12,mc);
  REAL y=152;for(auto&r:rows){if(y>h-60)break;DrawText(g,r.first,262,y,13,tc,true);bool ignored=g_ignoredApps.count(r.first)!=0;SolidBrush b(ignored?Color(255,232,241,255):Color(255,255,255));Pen p(Color(255,210,210,218),1);g.FillRectangle(&b,w-390,y-5,110,27);g.DrawRectangle(&p,w-390,y-5,110,27);DrawText(g,ignored?L"Excluded":L"Monitor",w-377,y+2,11,ignored?blue:tc,true);y+=39;}
  if(rows.empty())DrawText(g,L"Apps appear here after they have been monitored.",262,155,13,mc);
 }else{
  Card(g,240,92,w-264,250);DrawText(g,L"GENERAL",262,112,11,mc,true);DrawText(g,L"Run ScreenAudit when I sign in",262,153,14,tc);DrawText(g,g_startup?L"Enabled":L"Disabled",w-340,153,12,g_startup?blue:mc,true);
  DrawText(g,L"Click this row to toggle automatic startup.",262,181,11,mc);DrawText(g,L"Tracking",262,229,14,tc,true);DrawText(g,L"Idle cutoff: "+std::to_wstring(g_idleCutoff)+L" minutes",262,258,12,mc);
  Card(g,240,360,w-264,120);DrawText(g,L"BROWSER CONTEXT",262,380,11,mc,true);DrawText(g,L"Reads the active browser address-bar URL when available.",262,408,12,tc);DrawText(g,L"Recognized domains are labelled; full URLs are not stored.",262,434,11,mc);
 }
 Graphics target(hdc);target.DrawImage(&bmp,0,0);EndPaint(hwnd,&ps);
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
 if(c==103){SaveStartup(!g_startup);}
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
 case WM_LBUTTONUP:{
  int x=GET_X_LPARAM(lp),y=GET_Y_LPARAM(lp);
  if(x<220&&y>=92&&y<284){g_page=(y-92)/48;InvalidateRect(h,nullptr,TRUE);}
  else if(x>w-120&&y<60){FlushCurrent();g_tracking=!g_tracking;SaveSetting(L"Tracking",L"Enabled",g_tracking);g_lastTick=GetTickCount64();InvalidateRect(h,nullptr,TRUE);}
  else if(g_page==2&&x>w-410&&x<w-260&&y>=145){
   int idx=(y-147)/39;std::vector<std::pair<std::wstring,ULONGLONG>> r(g_usage.begin(),g_usage.end());std::sort(r.begin(),r.end(),[](auto&a,auto&b){return a.second>b.second;});
   if(idx>=0&&idx<(int)r.size()){auto name=r[idx].first;if(g_ignoredApps.count(name))g_ignoredApps.erase(name);else g_ignoredApps.insert(name);SaveIgnored();}
   InvalidateRect(h,nullptr,TRUE);
  }else if(g_page==3&&y>=135&&y<210){SaveStartup(!g_startup);InvalidateRect(h,nullptr,TRUE);}
  return 0;
 }
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
 DWORD ex=WS_EX_APPWINDOW;HWND h=CreateWindowExW(ex,wc.lpszClassName,APP_NAME,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,1180,780,nullptr,nullptr,inst,nullptr);
 if(!h)return 2;g_hwnd=h;
 BOOL dark=g_dark?TRUE:FALSE;DwmSetWindowAttribute(h,20,&dark,sizeof(dark));
 ShowWindow(h,SW_SHOW);UpdateWindow(h);
 MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 GdiplusShutdown(g_gdiplus);return 0;
}
