#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define _CRT_SECURE_NO_WARNINGS 
#include "Includes.hpp"
//#include <tlhelp32.h>
//#include <wininet.h>
//#include <winsock2.h>
#include <cstdint>
#include <intrin.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <map>
#include <unordered_map>
#include <iostream>
#include <Windows.h>
#include "minhook/MinHook.h"
#include <string.h>
#include <string>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <wininet.h>
#include <DbgHelp.h>
#include <unordered_map>
#include <sstream>
#include <deque>
#include <mutex>
#include <type_traits>
#include "zz.hpp"
#include "binary.h"
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

std::vector< std::tuple< uint32_t, std::string, std::string > > g_aImports =
{
{ 0x16882000, "ADVAPI32.dll", "RegCloseKey" },
{ 0x16882004, "ADVAPI32.dll", "RegCreateKeyExW" },
{ 0x16882008, "ADVAPI32.dll", "RegOpenKeyExW" },
{ 0x1688200c, "ADVAPI32.dll", "RegQueryValueExW" },
{ 0x16882010, "ADVAPI32.dll", "RegSetValueExW" },
{ 0x16882018, "IMM32.DLL", "ImmGetContext" },
{ 0x1688201c, "IMM32.DLL", "ImmSetCompositionWindow" },
{ 0x16882020, "IMM32.DLL", "ImmReleaseContext" },
{ 0x16882028, "KERNEL32.DLL", "QueryPerformanceCounter" },
{ 0x1688202c, "KERNEL32.DLL", "QueryPerformanceFrequency" },
{ 0x16882030, "KERNEL32.DLL", "VirtualAlloc" },
{ 0x16882034, "KERNEL32.DLL", "VirtualFree" },
{ 0x16882038, "KERNEL32.DLL", "VirtualQuery" },
{ 0x1688203c, "KERNEL32.DLL", "HeapCreate" },
{ 0x16882040, "KERNEL32.DLL", "HeapDestroy" },
{ 0x16882044, "ntdll.dll", "RtlAllocateHeap" },
{ 0x16882048, "ntdll.dll", "RtlReAllocateHeap" },
{ 0x1688204c, "KERNEL32.DLL", "HeapFree" },
{ 0x16882050, "KERNEL32.DLL", "GetCurrentProcess" },
{ 0x16882054, "KERNEL32.DLL", "GetCurrentProcessId" },
{ 0x16882058, "KERNEL32.DLL", "GetCurrentThreadId" },
{ 0x1688205c, "KERNEL32.DLL", "OpenThread" },
{ 0x16882060, "KERNEL32.DLL", "SuspendThread" },
{ 0x16882064, "KERNEL32.DLL", "ResumeThread" },
{ 0x16882068, "KERNEL32.DLL", "GetThreadContext" },
{ 0x1688206c, "KERNEL32.DLL", "SetThreadContext" },
{ 0x16882070, "KERNEL32.DLL", "FlushInstructionCache" },
{ 0x16882074, "KERNEL32.DLL", "VirtualProtect" },
{ 0x16882078, "KERNEL32.DLL", "GetModuleHandleW" },
{ 0x1688207c, "KERNEL32.DLL", "CreateToolhelp32Snapshot" },
{ 0x16882080, "KERNEL32.DLL", "Thread32First" },
{ 0x16882084, "KERNEL32.DLL", "Thread32Next" },
{ 0x16882088, "KERNEL32.DLL", "MultiByteToWideChar" },
{ 0x1688208c, "KERNEL32.DLL", "GlobalUnlock" },
{ 0x16882090, "KERNEL32.DLL", "WriteFile" },
{ 0x16882094, "KERNEL32.DLL", "GetLastError" },
{ 0x16882098, "KERNEL32.DLL", "PeekNamedPipe" },
{ 0x1688209c, "KERNEL32.DLL", "WaitNamedPipeW" },
{ 0x168820a0, "KERNEL32.DLL", "GetModuleFileNameW" },
{ 0x168820a4, "KERNEL32.DLL", "lstrlenW" },
{ 0x168820a8, "KERNEL32.DLL", "CreateThread" },
{ 0x168820ac, "KERNEL32.DLL", "DisableThreadLibraryCalls" },
{ 0x168820b0, "KERNEL32.DLL", "FreeLibraryAndExitThread" },
{ 0x168820b4, "KERNEL32.DLL", "GetSystemTimeAsFileTime" },
{ 0x168820b8, "KERNEL32.DLL", "TerminateProcess" },
{ 0x168820bc, "KERNEL32.DLL", "SetUnhandledExceptionFilter" },
{ 0x168820c0, "KERNEL32.DLL", "UnhandledExceptionFilter" },
{ 0x168820c4, "KERNEL32.DLL", "IsDebuggerPresent" },
{ 0x168820c8, "KERNEL32.DLL", "IsProcessorFeaturePresent" },
{ 0x168820cc, "KERNEL32.DLL", "CreateEventW" },
{ 0x168820d0, "KERNEL32.DLL", "WaitForSingleObjectEx" },
{ 0x168820d4, "KERNEL32.DLL", "ResetEvent" },
{ 0x168820d8, "KERNEL32.DLL", "SetEvent" },
{ 0x168820dc, "ntdll.dll", "RtlDeleteCriticalSection" },
{ 0x168820e0, "KERNEL32.DLL", "InitializeCriticalSectionAndSpinCount" },
{ 0x168820e4, "ntdll.dll", "RtlLeaveCriticalSection" },
{ 0x168820e8, "ntdll.dll", "RtlEnterCriticalSection" },
{ 0x168820ec, "KERNEL32.DLL", "WideCharToMultiByte" },
{ 0x168820f0, "KERNEL32.DLL", "GlobalFree" },
{ 0x168820f4, "KERNEL32.DLL", "CreateFileW" },
{ 0x168820f8, "KERNEL32.DLL", "GlobalLock" },
{ 0x168820fc, "ntdll.dll", "RtlInitializeSListHead" },
{ 0x16882100, "KERNEL32.DLL", "GlobalAlloc" },
{ 0x16882104, "KERNEL32.DLL", "K32GetModuleFileNameExW" },
{ 0x16882108, "KERNEL32.DLL", "OpenProcess" },
{ 0x1688210c, "KERNEL32.DLL", "CloseHandle" },
{ 0x16882110, "KERNEL32.DLL", "GetProcAddress" },
{ 0x16882114, "KERNEL32.DLL", "GetModuleHandleA" },
{ 0x16882118, "KERNEL32.DLL", "ReadFile" },
{ 0x1688211c, "KERNEL32.DLL", "Sleep" },
{ 0x16882124, "MSVCP140.dll", "_Query_perf_frequency" },
{ 0x16882128, "MSVCP140.dll", "_Query_perf_counter" },
{ 0x1688212c, "MSVCP140.dll", "?_Throw_Cpp_error@std@@YAXH@Z" },
{ 0x16882130, "MSVCP140.dll", "?_Throw_C_error@std@@YAXH@Z" },
{ 0x16882134, "MSVCP140.dll", "_Cnd_do_broadcast_at_thread_exit" },
{ 0x16882138, "MSVCP140.dll", "_Thrd_sleep" },
{ 0x1688213c, "MSVCP140.dll", "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAEPAV12@PAD_J@Z" },
{ 0x16882140, "MSVCP140.dll", "_Cnd_broadcast" },
{ 0x16882144, "MSVCP140.dll", "_Cnd_timedwait" },
{ 0x16882148, "MSVCP140.dll", "_Cnd_destroy_in_situ" },
{ 0x1688214c, "MSVCP140.dll", "_Cnd_init_in_situ" },
{ 0x16882150, "MSVCP140.dll", "_Mtx_unlock" },
{ 0x16882154, "MSVCP140.dll", "_Mtx_lock" },
{ 0x16882158, "MSVCP140.dll", "_Mtx_current_owns" },
{ 0x1688215c, "MSVCP140.dll", "_Mtx_destroy_in_situ" },
{ 0x16882160, "MSVCP140.dll", "_Mtx_init_in_situ" },
{ 0x16882164, "MSVCP140.dll", "?GetCurrentThreadId@platform@details@Concurrency@@YAJXZ" },
{ 0x16882168, "MSVCP140.dll", "?_Xlength_error@std@@YAXPBD@Z" },
{ 0x1688216c, "MSVCP140.dll", "?_Xout_of_range@std@@YAXPBD@Z" },
{ 0x16882170, "MSVCP140.dll", "??0_Lockit@std@@QAE@H@Z" },
{ 0x16882174, "MSVCP140.dll", "??1_Lockit@std@@QAE@XZ" },
{ 0x16882178, "MSVCP140.dll", "?_Xbad_alloc@std@@YAXXZ" },
{ 0x1688217c, "MSVCP140.dll", "??0_Locinfo@std@@QAE@PBD@Z" },
{ 0x16882180, "MSVCP140.dll", "??1_Locinfo@std@@QAE@XZ" },
{ 0x16882184, "MSVCP140.dll", "?_Getcvt@_Locinfo@std@@QBE?AU_Cvtvec@@XZ" },
{ 0x16882188, "MSVCP140.dll", "?_Getfalse@_Locinfo@std@@QBEPBDXZ" },
{ 0x1688218c, "MSVCP140.dll", "?_Gettrue@_Locinfo@std@@QBEPBDXZ" },
{ 0x16882190, "MSVCP140.dll", "?_C_str@?$_Yarn@D@std@@QBEPBDXZ" },
{ 0x16882194, "MSVCP140.dll", "??Bid@locale@std@@QAEIXZ" },
{ 0x16882198, "MSVCP140.dll", "??0facet@locale@std@@IAE@I@Z" },
{ 0x1688219c, "MSVCP140.dll", "??1?$codecvt@DDU_Mbstatet@@@std@@MAE@XZ" },
{ 0x168821a0, "MSVCP140.dll", "?_Init@locale@std@@CAPAV_Locimp@12@_N@Z" },
{ 0x168821a4, "MSVCP140.dll", "?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ" },
{ 0x168821a8, "MSVCP140.dll", "?_Decref@facet@locale@std@@UAEPAV_Facet_base@3@XZ" },
{ 0x168821ac, "MSVCP140.dll", "?_Incref@facet@locale@std@@UAEXXZ" },
{ 0x168821b0, "MSVCP140.dll", "?id@?$numpunct@D@std@@2V0locale@2@A" },
{ 0x168821b4, "MSVCP140.dll", "?uncaught_exceptions@std@@YAHXZ" },
{ 0x168821b8, "MSVCP140.dll", "?always_noconv@codecvt_base@std@@QBE_NXZ" },
{ 0x168821bc, "MSVCP140.dll", "?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z" },
{ 0x168821c0, "MSVCP140.dll", "?in@?$codecvt@DDU_Mbstatet@@@std@@QBEHAAU_Mbstatet@@PBD1AAPBDPAD3AAPAD@Z" },
{ 0x168821c4, "MSVCP140.dll", "?out@?$codecvt@DDU_Mbstatet@@@std@@QBEHAAU_Mbstatet@@PBD1AAPBDPAD3AAPAD@Z" },
{ 0x168821c8, "MSVCP140.dll", "?unshift@?$codecvt@DDU_Mbstatet@@@std@@QBEHAAU_Mbstatet@@PAD1AAPAD@Z" },
{ 0x168821cc, "MSVCP140.dll", "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SAIPAPBVfacet@locale@2@PBV42@@Z" },
{ 0x168821d0, "MSVCP140.dll", "?getloc@ios_base@std@@QBE?AVlocale@2@XZ" },
{ 0x168821d4, "MSVCP140.dll", "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IAE@XZ" },
{ 0x168821d8, "MSVCP140.dll", "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UAE@XZ" },
{ 0x168821dc, "MSVCP140.dll", "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QBE?AVlocale@2@XZ" },
{ 0x168821e0, "MSVCP140.dll", "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ" },
{ 0x168821e4, "MSVCP140.dll", "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ" },
{ 0x168821e8, "MSVCP140.dll", "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ" },
{ 0x168821ec, "MSVCP140.dll", "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHD@Z" },
{ 0x168821f0, "MSVCP140.dll", "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAE_JPBD_J@Z" },
{ 0x168821f4, "MSVCP140.dll", "?_Gndec@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IAEPADXZ" },
{ 0x168821f8, "MSVCP140.dll", "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IAEPADXZ" },
{ 0x168821fc, "MSVCP140.dll", "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IAEXXZ" },
{ 0x16882200, "MSVCP140.dll", "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JPAD_J@Z" },
{ 0x16882204, "MSVCP140.dll", "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JPBD_J@Z" },
{ 0x16882208, "MSVCP140.dll", "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UAE@XZ" },
{ 0x1688220c, "MSVCP140.dll", "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z" },
{ 0x16882210, "MSVCP140.dll", "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z" },
{ 0x16882214, "MSVCP140.dll", "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IAE@XZ" },
{ 0x16882218, "MSVCP140.dll", "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z" },
{ 0x1688221c, "MSVCP140.dll", "??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UAE@XZ" },
{ 0x16882220, "MSVCP140.dll", "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEXXZ" },
{ 0x16882224, "MSVCP140.dll", "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV12@XZ" },
{ 0x16882228, "MSVCP140.dll", "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z" },
{ 0x1688222c, "MSVCP140.dll", "??1?$basic_istream@DU?$char_traits@D@std@@@std@@UAE@XZ" },
{ 0x16882230, "MSVCP140.dll", "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z" },
{ 0x16882234, "MSVCP140.dll", "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z" },
{ 0x16882238, "MSVCP140.dll", "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UAE@XZ" },
{ 0x1688223c, "MSVCP140.dll", "?_Fiopen@std@@YAPAU_iobuf@@PBDHH@Z" },
{ 0x16882240, "MSVCP140.dll", "?_Xbad_function_call@std@@YAXXZ" },
{ 0x16882244, "MSVCP140.dll", "?ReportUnhandledError@_ExceptionHolder@details@Concurrency@@AAEXXZ" },
{ 0x16882248, "MSVCP140.dll", "?ReportUnhandledError@_ExceptionHolder@details@Concurrency@@AAEXXZ" },
{ 0x1688224c, "MSVCP140.dll", "?_Assign@_ContextCallback@details@Concurrency@@AAEXPAX@Z" },
{ 0x16882250, "MSVCP140.dll", "_Thrd_join" },
{ 0x16882254, "MSVCP140.dll", "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAE_JXZ" },
{ 0x16882258, "MSVCP140.dll", "?do_encoding@?$codecvt@_SDU_Mbstatet@@@std@@MBEHXZ" },
{ 0x1688225c, "MSVCP140.dll", "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MAEHXZ" },
{ 0x16882260, "MSVCP140.dll", "?id@?$ctype@D@std@@2V0locale@2@A" },
{ 0x16882264, "MSVCP140.dll", "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A" },
{ 0x16882268, "MSVCP140.dll", "?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A" },
{ 0x1688226c, "MSVCP140.dll", "_Xtime_get_ticks" },
{ 0x16882274, "SHELL32.dll", "ShellExecuteA" },
{ 0x1688227c, "USER32.dll", "GetCapture" },
{ 0x16882280, "USER32.dll", "SetCapture" },
{ 0x16882284, "USER32.dll", "ReleaseCapture" },
{ 0x16882288, "USER32.dll", "GetForegroundWindow" },
{ 0x1688228c, "USER32.dll", "GetClientRect" },
{ 0x16882290, "USER32.dll", "SetCursorPos" },
{ 0x16882294, "USER32.dll", "LoadCursorA" },
{ 0x16882298, "USER32.dll", "ScreenToClient" },
{ 0x1688229c, "USER32.dll", "ClientToScreen" },
{ 0x168822a0, "USER32.dll", "GetCursorPos" },
{ 0x168822a4, "USER32.dll", "GetKeyState" },
{ 0x168822a8, "USER32.dll", "IsChild" },
{ 0x168822ac, "USER32.dll", "FindWindowW" },
{ 0x168822b0, "USER32.dll", "SetWindowLongW" },
{ 0x168822b4, "USER32.dll", "SetWindowLongA" },
{ 0x168822b8, "USER32.dll", "GetAsyncKeyState" },
{ 0x168822bc, "USER32.dll", "IsWindowVisible" },
{ 0x168822c0, "USER32.dll", "GetWindowTextW" },
{ 0x168822c4, "USER32.dll", "GetWindowTextLengthW" },
{ 0x168822c8, "USER32.dll", "GetTopWindow" },
{ 0x168822cc, "USER32.dll", "GetWindowThreadProcessId" },
{ 0x168822d0, "USER32.dll", "GetWindow" },
{ 0x168822d4, "USER32.dll", "OpenClipboard" },
{ 0x168822d8, "USER32.dll", "SetCursor" },
{ 0x168822dc, "USER32.dll", "CloseClipboard" },
{ 0x168822e0, "USER32.dll", "SetClipboardData" },
{ 0x168822e4, "USER32.dll", "GetClipboardData" },
{ 0x168822e8, "USER32.dll", "EmptyClipboard" },
{ 0x168822ec, "USER32.dll", "GetActiveWindow" },
{ 0x168822f0, "USER32.dll", "CallWindowProcA" },
{ 0x168822f8, "VCRUNTIME140.dll", "__current_exception_context" },
{ 0x168822fc, "VCRUNTIME140.dll", "_except_handler4_common" },
{ 0x16882300, "VCRUNTIME140.dll", "__std_type_info_destroy_list" },
{ 0x16882304, "VCRUNTIME140.dll", "__current_exception" },
{ 0x16882308, "VCRUNTIME140.dll", "__std_exception_copy" },
{ 0x1688230c, "VCRUNTIME140.dll", "__std_exception_destroy" },
{ 0x16882310, "VCRUNTIME140.dll", "_CxxThrowException" },
{ 0x16882314, "VCRUNTIME140.dll", "__CxxFrameHandler" },
{ 0x16882318, "VCRUNTIME140.dll", "memset" },
{ 0x1688231c, "VCRUNTIME140.dll", "__std_terminate" },
{ 0x16882320, "VCRUNTIME140.dll", "memcpy" },
{ 0x16882324, "VCRUNTIME140.dll", "memcpy" },
{ 0x16882328, "VCRUNTIME140.dll", "memchr" },
{ 0x1688232c, "VCRUNTIME140.dll", "memcmp" },
{ 0x16882330, "VCRUNTIME140.dll", "strstr" },
{ 0x16882334, "VCRUNTIME140.dll", "_purecall" },
{ 0x1688233c, "XInput1_4.dll", "XInputGetCapabilities" },
{ 0x16882340, "XInput1_4.dll", "XInputGetState" },
{ 0x16882348, "ucrtbase.dll", "strtod" },
{ 0x1688234c, "ucrtbase.dll", "strtoul" },
{ 0x16882350, "ucrtbase.dll", "_strtoi64" },
{ 0x16882354, "ucrtbase.dll", "atof" },
{ 0x16882358, "ucrtbase.dll", "_strtoui64" },
{ 0x16882360, "ucrtbase.dll", "_lock_file" },
{ 0x16882364, "ucrtbase.dll", "_unlock_file" },
{ 0x1688236c, "ucrtbase.dll", "_callnewh" },
{ 0x16882370, "ucrtbase.dll", "free" },
{ 0x16882374, "ucrtbase.dll", "calloc" },
{ 0x16882378, "ucrtbase.dll", "malloc" },
{ 0x16882380, "ucrtbase.dll", "localeconv" },
{ 0x16882388, "ucrtbase.dll", "_dclass" },
{ 0x1688238c, "ucrtbase.dll", "_libm_sse2_atan_precise" },
{ 0x16882390, "ucrtbase.dll", "_libm_sse2_cos_precise" },
{ 0x16882394, "ucrtbase.dll", "_libm_sse2_sin_precise" },
{ 0x16882398, "ucrtbase.dll", "floor" },
{ 0x1688239c, "ucrtbase.dll", "_libm_sse2_sqrt_precise" },
{ 0x168823a0, "ucrtbase.dll", "_fdclass" },
{ 0x168823a4, "ucrtbase.dll", "_dclass" },
{ 0x168823a8, "ucrtbase.dll", "_libm_sse2_tan_precise" },
{ 0x168823ac, "ucrtbase.dll", "_libm_sse2_pow_precise" },
{ 0x168823b0, "ucrtbase.dll", "_fdsign" },
{ 0x168823b4, "ucrtbase.dll", "_CIatan2" },
{ 0x168823b8, "ucrtbase.dll", "_CIfmod" },
{ 0x168823bc, "ucrtbase.dll", "_dsign" },
{ 0x168823c0, "ucrtbase.dll", "remainderf" },
{ 0x168823c4, "ucrtbase.dll", "_dsign" },
{ 0x168823c8, "ucrtbase.dll", "log2" },
{ 0x168823cc, "ucrtbase.dll", "_libm_sse2_log_precise" },
{ 0x168823d0, "ucrtbase.dll", "_hypotf" },
{ 0x168823d4, "ucrtbase.dll", "_libm_sse2_acos_precise" },
{ 0x168823d8, "ucrtbase.dll", "ceil" },
{ 0x168823e0, "ucrtbase.dll", "_wassert" },
{ 0x168823e4, "ucrtbase.dll", "_errno" },
{ 0x168823e8, "ucrtbase.dll", "_initterm" },
{ 0x168823ec, "ucrtbase.dll", "_initterm_e" },
{ 0x168823f0, "ucrtbase.dll", "terminate" },
{ 0x168823f4, "ucrtbase.dll", "_invalid_parameter_noinfo_noreturn" },
{ 0x168823f8, "ucrtbase.dll", "_beginthreadex" },
{ 0x168823fc, "ucrtbase.dll", "_cexit" },
{ 0x16882400, "ucrtbase.dll", "_crt_atexit" },
{ 0x16882404, "ucrtbase.dll", "_execute_onexit_table" },
{ 0x16882408, "ucrtbase.dll", "_seh_filter_dll" },
{ 0x1688240c, "ucrtbase.dll", "_configure_narrow_argv" },
{ 0x16882410, "ucrtbase.dll", "_initialize_narrow_environment" },
{ 0x16882414, "ucrtbase.dll", "_initialize_onexit_table" },
{ 0x16882418, "ucrtbase.dll", "_register_onexit_function" },
{ 0x16882420, "ucrtbase.dll", "ftell" },
{ 0x16882424, "ucrtbase.dll", "_get_stream_buffer_pointers" },
{ 0x16882428, "ucrtbase.dll", "__stdio_common_vfprintf" },
{ 0x1688242c, "ucrtbase.dll", "fclose" },
{ 0x16882430, "ucrtbase.dll", "fseek" },
{ 0x16882434, "ucrtbase.dll", "_wfopen" },
{ 0x16882438, "ucrtbase.dll", "fflush" },
{ 0x1688243c, "ucrtbase.dll", "__stdio_common_vswprintf" },
{ 0x16882440, "ucrtbase.dll", "__acrt_iob_func" },
{ 0x16882444, "ucrtbase.dll", "__stdio_common_vsprintf" },
{ 0x16882448, "ucrtbase.dll", "ungetc" },
{ 0x1688244c, "ucrtbase.dll", "__stdio_common_vsscanf" },
{ 0x16882450, "ucrtbase.dll", "setvbuf" },
{ 0x16882454, "ucrtbase.dll", "fwrite" },
{ 0x16882458, "ucrtbase.dll", "fgetc" },
{ 0x1688245c, "ucrtbase.dll", "_fseeki64" },
{ 0x16882460, "ucrtbase.dll", "fsetpos" },
{ 0x16882464, "ucrtbase.dll", "fread" },
{ 0x16882468, "ucrtbase.dll", "fputc" },
{ 0x1688246c, "ucrtbase.dll", "fgetpos" },
{ 0x16882474, "ucrtbase.dll", "toupper" },
{ 0x16882478, "ucrtbase.dll", "strncpy" },
{ 0x1688247c, "ucrtbase.dll", "strcpy_s" },
{ 0x16882484, "ucrtbase.dll", "_time64" },
{ 0x1688248c, "ucrtbase.dll", "qsort" },
{ 0x16882490, "ucrtbase.dll", "rand" },
		
};


void Init()
{
	void* hack_address = reinterpret_cast<void*>(0x16800000);


	printf("[+] Checking memory...\n");


	
		MEMORY_BASIC_INFORMATION mem;
	    if (!VirtualQuery(reinterpret_cast<void*>(0x16800000), &mem, sizeof(mem)))
	    {
	    	printf("[-] failed, restart steam and inject steam_module please\n");
	    	Sleep(3000);
	    	TerminateProcess(reinterpret_cast<HANDLE>(-1), 0);
	    }
	
	
	printf("[+] Init cheat...\n");
	memcpy(hack_address, rawData, 0x119000);
	printf("[+] cheat inited!\n");

	printf("[+] waiting for serverbrowser.dll...\n");
	while (!GetModuleHandleA("serverbrowser.dll")) Sleep(100);
	printf("[+] serverbrowser.dll founted\n");

	printf("[+] Fixing imports...\n");

	for (const auto& CurrentImport : g_aImports)
	{
		HMODULE hModule = LoadLibraryA(std::get< 1 >(CurrentImport).c_str());
		if (!hModule)
			continue;

		uint32_t pFunction = (uint32_t)GetProcAddress(hModule, std::get< 2 >(CurrentImport).c_str());
		if (!pFunction)
			continue;

		*reinterpret_cast<uint32_t*>(std::get< 0 >(CurrentImport)) = pFunction;
	}
	printf("[+] Imports fixed!\n");

	printf("[+] calling ep...\n");


	using DllEntry_t = BOOL(__stdcall*) (void*, DWORD, void*);
	(reinterpret_cast<DllEntry_t>(0x1687D41F))(reinterpret_cast<void*>(0x16800000),
		DLL_PROCESS_ATTACH, 0);

	printf("[+] Ep called\n");

}

int main()
{
	printf("Femboyhook.xyz patcher\n");
	Init();
	return 0;
}







bool __stdcall DllMain(HANDLE hinstDLL, uint32_t fdwReason, void* lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		SetConsoleTitleA("Femboyhook.xyz patcher");
		freopen("CONOUT$", "w", stdout);
		CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(main), 0, 0, 0);
	}
	return true;
}

