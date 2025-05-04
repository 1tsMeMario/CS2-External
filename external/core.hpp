#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <tchar.h>
#include <random>
#include <mutex>
#include <functional>
#include <TlHelp32.h>
#include <Psapi.h>
#include <thread>
#include <chrono>
#include <xorstr.hpp>

#include <d3d11.h>
#include <dwmapi.h>

#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")

#define DEBUG_OUTPUT false

#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

SYSTEM_HANDLE_INFORMATION* hInfo;

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, version, url, path;
		static bool debug;

		api(std::string name, std::string ownerid, std::string version, std::string url, std::string path, bool debugParameter = false)
			: name(name), ownerid(ownerid), version(version), url(url), path(path)
		{
			setDebug(debugParameter);
		}

		void ban(std::string reason = "");
		void init();
		void check(bool check_paid = false);
		void log(std::string msg);
		void license(std::string key, std::string code = "");
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body = "", std::string contenttype = "");
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password, std::string code = "");
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key, std::string email = "");
		void chatget(std::string channel);
		bool chatsend(std::string message, std::string channel);
		void changeUsername(std::string newusername);
		std::string fetchonline();
		void fetchstats();
		void forgot(std::string username, std::string email);
		void logout();

		class subscriptions_class {
		public:
			std::string name;
			std::string expiry;
		};

		class userdata {
		public:

			// user data
			std::string username;
			std::string ip;
			std::string hwid;
			std::string createdate;
			std::string lastlogin;

			std::vector<subscriptions_class> subscriptions;
		};

		class appdata {
		public:
			// app data
			std::string numUsers;
			std::string numOnlineUsers;
			std::string numKeys;
			std::string version;
			std::string customerPanelLink;
			std::string downloadLink;
		};

		class responsedata {
		public:
			// response data
			std::vector<channel_struct> channeldata;
			bool success{};
			std::string message;
			bool isPaid{};
		};

		bool activate = false;
		class Tfa {
		public:
			std::string secret;
			std::string link;
			Tfa& handleInput(KeyAuth::api& apiInstance);
		private:
			void QrCode();
		};

		Tfa& enable2fa(std::string code = "");
		Tfa& disable2fa(std::string code = "");

		userdata user_data;
		appdata app_data;
		responsedata response;
		Tfa tfa;

	private:
		std::string sessionid, enckey;
		static void setDebug(bool value);
	};
}

typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static UINT g_ResizeWidth, g_ResizeHeight;

class Logger
{
private:
	bool messagebox = false;
	HWND console_hwnd = nullptr;
	FILE* fIn = nullptr;
	FILE* fOut = nullptr;
	FILE* fErr = nullptr;
	bool allocated = false;
	bool reallocated = false;
public:

	void create_console(const char* title = "Debug Console") {
		if (allocated) return;

		AllocConsole();
		SetConsoleTitleA(title);

		freopen_s(&fOut, "CONOUT$", "w", stdout);
		freopen_s(&fIn, "CONIN$", "r", stdin);
		freopen_s(&fErr, "CONOUT$", "w", stderr);

		std::ios::sync_with_stdio();

		allocated = true;
	}

	void close_console() {
		if (!allocated) return;

		if (fIn) { fclose(fIn);  fIn = nullptr; }
		if (fOut) { fclose(fOut); fOut = nullptr; }
		if (fErr) { fclose(fErr); fErr = nullptr; }

		FreeConsole();
		allocated = false;
	}
	void message(const char* format, ...)
	{
		if (messagebox)
		{
			char buffer[1024];
			va_list args;
			va_start(args, format);
			vsnprintf(buffer, sizeof(buffer), format, args);
			va_end(args);
			MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK);
		}
		else
		{
			if (!allocated)
			{
				create_console();
				reallocated = true;
			}
			std::cout << xorstr_("[Athena Development] ");
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
			std::cout << std::endl;
			if (reallocated)
			{
				console_hwnd = GetConsoleWindow();

				if (IsIconic(console_hwnd)) {
					ShowWindow(console_hwnd, SW_RESTORE);
				}

				SetForegroundWindow(console_hwnd);
				SetActiveWindow(console_hwnd);
				SetFocus(console_hwnd);
				Sleep(3000);
				close_console();
				reallocated = false;
			}
		}
	}

	void info(const char* format, ...)
	{
		if (messagebox)
		{
			char buffer[1024];
			va_list args;
			va_start(args, format);
			vsnprintf(buffer, sizeof(buffer), format, args);
			va_end(args);
			MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK | MB_ICONINFORMATION);
		}
		else
		{
			if (!allocated)
			{
				create_console();
				reallocated = true;
			}
			std::cout << xorstr_("[Athena Development] ");
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
			std::cout << std::endl;
			if (reallocated)
			{
				console_hwnd = GetConsoleWindow();

				if (IsIconic(console_hwnd)) {
					ShowWindow(console_hwnd, SW_RESTORE);
				}

				SetForegroundWindow(console_hwnd);
				SetActiveWindow(console_hwnd);
				SetFocus(console_hwnd);
				Sleep(3000);
				close_console();
				reallocated = false;
			}
		}
	}

	void debug(const char* format, ...)
	{
		if (DEBUG_OUTPUT == true)
		{
			if (messagebox)
			{
				char buffer[1024];
				va_list args;
				va_start(args, format);
				vsnprintf(buffer, sizeof(buffer), format, args);
				va_end(args);
				MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK | MB_ICONASTERISK);
			}
			else
			{
				if (!allocated)
				{
					create_console();
					reallocated = true;
				}
				std::cout << xorstr_("[Athena Development] ");
				va_list args;
				va_start(args, format);
				vprintf(format, args);
				va_end(args);
				std::cout << std::endl;
				if (reallocated)
				{
					console_hwnd = GetConsoleWindow();

					if (IsIconic(console_hwnd)) {
						ShowWindow(console_hwnd, SW_RESTORE);
					}

					SetForegroundWindow(console_hwnd);
					SetActiveWindow(console_hwnd);
					SetFocus(console_hwnd);
					Sleep(3000);
					close_console();
					reallocated = false;
				}
			}
		}
	}

	void warning(const char* format, ...)
	{
		if (messagebox)
		{
			char buffer[1024];
			va_list args;
			va_start(args, format);
			vsnprintf(buffer, sizeof(buffer), format, args);
			va_end(args);
			MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK | MB_ICONEXCLAMATION);
		}
		else
		{
			if (!allocated)
			{
				create_console();
				reallocated = true;
			}
			std::cout << xorstr_("[Athena Development] ");
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
			std::cout << std::endl;
			console_hwnd = GetConsoleWindow();
			if (IsIconic(console_hwnd)) {
				ShowWindow(console_hwnd, SW_RESTORE);
			}

			SetForegroundWindow(console_hwnd);
			SetActiveWindow(console_hwnd);
			SetFocus(console_hwnd);
			Sleep(3000);
			if (reallocated)
			{
				close_console();
				reallocated = false;
			}
		}
	}

	void error(const char* format, ...)
	{
		if (messagebox)
		{
			char buffer[1024];
			va_list args;
			va_start(args, format);
			vsnprintf(buffer, sizeof(buffer), format, args);
			va_end(args);
			MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK | MB_ICONERROR);
			exit(-1);
		}
		else
		{
			if (!allocated)
			{
				create_console();
				reallocated = true;
			}
			std::cout << xorstr_("[Athena Development] ");
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
			std::cout << std::endl;
			console_hwnd = GetConsoleWindow();

			if (IsIconic(console_hwnd)) {
				ShowWindow(console_hwnd, SW_RESTORE);
			}

			SetForegroundWindow(console_hwnd);
			SetActiveWindow(console_hwnd);
			SetFocus(console_hwnd);
			Sleep(3000);
			if (reallocated)
			{
				close_console();
				reallocated = false;
			}
			exit(-1);
		}
	}

	bool ask(const char* format, ...)
	{
		if (messagebox)
		{
			char buffer[1024];
			va_list args;
			va_start(args, format);
			vsnprintf(buffer, sizeof(buffer), format, args);
			va_end(args);
			if (MessageBoxA(nullptr, buffer, xorstr_("Athena Development"), MB_OK | MB_ICONERROR) == IDYES)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			if(!allocated)
			{
				create_console();
				reallocated = true;
			}
			std::cout << xorstr_("[Athena Development] ");
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
			console_hwnd = GetConsoleWindow();

			if (IsIconic(console_hwnd)) {
				ShowWindow(console_hwnd, SW_RESTORE);
			}

			SetForegroundWindow(console_hwnd);
			SetActiveWindow(console_hwnd);
			SetFocus(console_hwnd);
			std::string id_ask;
			std::cin >> id_ask;
			if (id_ask == xorstr_("Y") || id_ask == xorstr_("y"))
			{
				std::cout << std::endl;
				if (reallocated)
				{
					close_console();
					reallocated = false;
				}
				return true;
			}
			std::cout << std::endl;
			if (reallocated)
			{
				close_console();
				reallocated = false;
			}
			return false;
		}
	}
}; inline Logger logger{};

namespace librarys
{
	HMODULE user32;
	HMODULE win32u;
	HMODULE ntdll;
	bool init()
	{
		HMODULE user32_lib = LoadLibrary(xorstr_(L"user32.dll"));
		if (!user32_lib)
		{
			logger.debug(xorstr_("Failed to load user32.dll"));
			return false;
		}
		HMODULE win32u_lib = LoadLibrary(xorstr_(L"win32u.dll"));
		if (!win32u_lib)
		{
			logger.debug(xorstr_("Failed to load win32u.dll"));
			return false;
		}
		user32 = GetModuleHandle(xorstr_(L"user32.dll"));
		if (!user32)
		{
			logger.debug(xorstr_("Failed to get module handle user32.dll"));
			return false;
		}
		win32u = GetModuleHandle(xorstr_(L"win32u.dll"));
		if (!win32u)
		{
			logger.debug(xorstr_("Failed to get module handle win32u.dll"));
			return false;
		}
		ntdll = GetModuleHandle(xorstr_(L"ntdll.dll"));
		if (!ntdll)
		{
			logger.debug(xorstr_("Failed to get module handle ntdll.dll"));
			return false;
		}

		return true;
	}
}

namespace hj {
	HANDLE procHandle = NULL;

	OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
	{
		OBJECT_ATTRIBUTES object;

		object.Length = sizeof(OBJECT_ATTRIBUTES);
		object.ObjectName = name;
		object.Attributes = attributes;
		object.RootDirectory = hRoot;
		object.SecurityDescriptor = security;

		return object;
	}

	bool IsHandleValid(HANDLE handle)
	{
		if (handle && handle != INVALID_HANDLE_VALUE)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	HANDLE HijackExistingHandle(DWORD dwTargetProcessId)
	{
		auto RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(librarys::ntdll, xorstr_("RtlAdjustPrivilege"));
		auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(librarys::ntdll, xorstr_("NtQuerySystemInformation"));
		auto NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(librarys::ntdll, xorstr_("NtDuplicateObject"));
		auto NtOpenProcess = (_NtOpenProcess)GetProcAddress(librarys::ntdll, xorstr_("NtOpenProcess"));

		if (!RtlAdjustPrivilege || !NtQuerySystemInformation || !NtDuplicateObject || !NtOpenProcess) {
			logger.error(xorstr_("One or more necessary functions not found in ntdll.dll."));
			return NULL;
		}

		BOOLEAN OldPriv;
		if (!NT_SUCCESS(RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv))) {
			logger.warning(xorstr_("Failed to adjust SeDebugPrivilege. Please run game as admin"));
		}

		OBJECT_ATTRIBUTES Obj_Attribute = {};
		Obj_Attribute.Length = sizeof(OBJECT_ATTRIBUTES);

		CLIENT_ID clientID = {};
		DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
		BYTE* buffer = nullptr;
		SYSTEM_HANDLE_INFORMATION* hInfo = nullptr;
		HANDLE procHandle = NULL;
		HANDLE hHijacked = NULL;

		NTSTATUS NtRet = 0;

		do {
			delete[] buffer;
			size = static_cast<DWORD>(size * 1.5);

			try {
				buffer = new BYTE[size];
				ZeroMemory(buffer, size);
				hInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer);
			}
			catch (const std::bad_alloc&) {
				logger.error(xorstr_("Memory allocation failed for handle information."));
				return NULL;
			}

			NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL);
			Sleep(1);

		} while (NtRet == STATUS_INFO_LENGTH_MISMATCH);

		if (!NT_SUCCESS(NtRet)) {
			logger.error(xorstr_("NtQuerySystemInformation failed to retrieve handle list."));
			delete[] buffer;
			return NULL;
		}

		for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
		{
			DWORD ownerPid = hInfo->Handles[i].ProcessId;

			if (ownerPid != dwTargetProcessId)
				continue;

			HANDLE rawHandle = (HANDLE)(ULONG_PTR)hInfo->Handles[i].Handle;

			if (!rawHandle || rawHandle == INVALID_HANDLE_VALUE)
				continue;

			if (hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
				continue;

			clientID.UniqueProcess = reinterpret_cast<PVOID>((ULONG_PTR)ownerPid);
			clientID.UniqueThread = 0;

			if (procHandle)
			{
				CloseHandle(procHandle);
				procHandle = NULL;
			}

			NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
			if (!procHandle || !NT_SUCCESS(NtRet)) {
				continue;
			}

			HANDLE tempHandle = NULL;
			NtRet = NtDuplicateObject(procHandle, rawHandle, NtCurrentProcess, &tempHandle,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
				0, 0);

			if (!NT_SUCCESS(NtRet) || !IsHandleValid(tempHandle)) {
				if (tempHandle) {
					CloseHandle(tempHandle);
				}
				continue;
			}

			DWORD hijackedPid = GetProcessId(tempHandle);

			if (hijackedPid == dwTargetProcessId) {
				hHijacked = tempHandle;
				break;
			}
			CloseHandle(tempHandle);
		}

		if (procHandle)
			CloseHandle(procHandle);

		delete[] buffer;

		return hHijacked;
	}
}

class pMemory {

public:
	pMemory() {
		pfnNtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(librarys::ntdll, xorstr_("NtReadVirtualMemory"));
		pfnNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(librarys::ntdll, xorstr_("NtWriteVirtualMemory"));
	}

	pNtReadVirtualMemory pfnNtReadVirtualMemory;
	pNtWriteVirtualMemory pfnNtWriteVirtualMemory;
};

struct ProcessModule
{
	uintptr_t base, size;
};

class pProcess
{
public:
	DWORD		  pid_;
	HANDLE		  handle_;
	HWND		  hwnd_;
	ProcessModule base_client_;

public:
	bool AttachProcess(const char* process_name)
	{
		this->pid_ = this->FindProcessIdByProcessName(process_name);

		if (pid_)
		{
			HMODULE modules[0xFF];
			MODULEINFO module_info;
			DWORD _;

			handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);

			EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
			base_client_.base = (uintptr_t)modules[0];

			GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
			base_client_.size = module_info.SizeOfImage;

			hwnd_ = this->GetWindowHandleFromProcessId(pid_);

			return true;
		}

		return false;
	}
	bool AttachProcessHj(const char* process_name, bool fallback_to_normal_attach)
	{
		this->pid_ = this->FindProcessIdByProcessName(process_name);

		if (pid_)
		{
			HMODULE modules[0xFF];
			MODULEINFO module_info;
			DWORD _;

			handle_ = hj::HijackExistingHandle(pid_);

			if (!hj::IsHandleValid(handle_))
			{
				if (fallback_to_normal_attach)
				{
					logger.warning(xorstr_("Handle Hijack failed, using fallback method. Risk is higher"));
					return pProcess::AttachProcess(process_name);
				}
				else
				{
					logger.error(xorstr_("Handle Hijack Failed"));
					return false;
				}
			}

			EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
			base_client_.base = (uintptr_t)modules[0];

			GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
			base_client_.size = module_info.SizeOfImage;

			hwnd_ = this->GetWindowHandleFromProcessId(pid_);

			return true;
		}

		return false;
	}
	bool AttachWindow(const char* window_name)
	{
		this->pid_ = this->FindProcessIdByWindowName(window_name);

		if (pid_)
		{
			HMODULE modules[0xFF];
			MODULEINFO module_info;
			DWORD _;

			handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);

			EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
			base_client_.base = (uintptr_t)modules[0];

			GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
			base_client_.size = module_info.SizeOfImage;

			hwnd_ = this->GetWindowHandleFromProcessId(pid_);

			return true;
		}
		return false;
	}
	bool UpdateHWND()
	{
		hwnd_ = this->GetWindowHandleFromProcessId(pid_);
		return hwnd_ == nullptr;
	}
	void Close()
	{
		CloseHandle(handle_);
	}

public:
	ProcessModule GetModule(const char* module_name)
	{
		std::wstring wideModule;
		int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, module_name, -1, nullptr, 0);
		if (wideCharLength > 0)
		{
			wideModule.resize(wideCharLength);
			MultiByteToWideChar(CP_UTF8, 0, module_name, -1, &wideModule[0], wideCharLength);
		}

		HANDLE handle_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_);
		MODULEENTRY32W module_entry_{};
		module_entry_.dwSize = sizeof(MODULEENTRY32W);

		do
		{
			if (!wcscmp(module_entry_.szModule, wideModule.c_str()))
			{
				CloseHandle(handle_module);
				return { (DWORD_PTR)module_entry_.modBaseAddr, module_entry_.dwSize };
			}
		} while (Module32NextW(handle_module, &module_entry_));

		CloseHandle(handle_module);
		return { 0, 0 };
	}
	LPVOID		  Allocate(size_t size_in_bytes)
	{
		return VirtualAllocEx(this->handle_, NULL, size_in_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	uintptr_t	  FindCodeCave(uint32_t length_in_bytes)
	{
		std::vector<uint8_t> cave_pattern = {};

		for (uint32_t i = 0; i < length_in_bytes; i++) {
			cave_pattern.push_back(0x00);
		}

		return FindSignature(cave_pattern);
	}
	uintptr_t     FindSignature(std::vector<uint8_t> signature)
	{
		std::unique_ptr<uint8_t[]> data;
		data = std::make_unique<uint8_t[]>(this->base_client_.size);

		if (!ReadProcessMemory(this->handle_, (void*)(this->base_client_.base), data.get(), this->base_client_.size, NULL)) {
			return 0x0;
		}

		for (uintptr_t i = 0; i < this->base_client_.size; i++)
		{
			for (uintptr_t j = 0; j < signature.size(); j++)
			{
				if (signature.at(j) == 0x00)
					continue;

				if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
				{
					if (j == signature.size() - 1)
						return this->base_client_.base + i;
					continue;
				}
				break;
			}
		}
		return 0x0;
	}
	uintptr_t     FindSignature(ProcessModule target_module, std::vector<uint8_t> signature)
	{
		std::unique_ptr<uint8_t[]> data;
		data = std::make_unique<uint8_t[]>(0xFFFFFFF);

		if (!ReadProcessMemory(this->handle_, (void*)(target_module.base), data.get(), 0xFFFFFFF, NULL)) {
			return NULL;
		}

		for (uintptr_t i = 0; i < 0xFFFFFFF; i++)
		{
			for (uintptr_t j = 0; j < signature.size(); j++)
			{
				if (signature.at(j) == 0x00)
					continue;

				if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
				{
					if (j == signature.size() - 1)
						return this->base_client_.base + i;
					continue;
				}
				break;
			}
		}
		return 0x0;
	}

	bool read_raw(uintptr_t address, void* buffer, size_t size)
	{
		SIZE_T bytesRead;
		pMemory cMemory;

		if (cMemory.pfnNtReadVirtualMemory(this->handle_, (PVOID)(address), buffer, static_cast<ULONG>(size), (PULONG)&bytesRead))
		{
			return bytesRead == size;
		}
		return false;
	}

	template<class T>
	void write(uintptr_t address, T value)
	{
		pMemory cMemory;
		cMemory.pfnNtWriteVirtualMemory(handle_, (void*)address, &value, sizeof(T), 0);
	}

	template<class T>
	T read(uintptr_t address)
	{
		T buffer{};
		pMemory cMemory;
#pragma warning(disable: 4267)
		cMemory.pfnNtReadVirtualMemory(handle_, (void*)address, &buffer, sizeof(T), 0);
		return buffer;
	}

	void write_bytes(uintptr_t addr, std::vector<uint8_t> patch)
	{
		pMemory cMemory;
		cMemory.pfnNtWriteVirtualMemory(handle_, (void*)addr, &patch[0], patch.size(), 0);
	}

private:
	uint32_t FindProcessIdByProcessName(const char* process_name)
	{
		std::wstring wideProcessName;
		int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, process_name, -1, nullptr, 0);
		if (wideCharLength > 0)
		{
			wideProcessName.resize(wideCharLength);
			MultiByteToWideChar(CP_UTF8, 0, process_name, -1, &wideProcessName[0], wideCharLength);
		}

		HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		PROCESSENTRY32W process_entry_{ };
		process_entry_.dwSize = sizeof(PROCESSENTRY32W);

		DWORD pid = 0;
		if (Process32FirstW(hPID, &process_entry_))
		{
			do
			{
				if (!wcscmp(process_entry_.szExeFile, wideProcessName.c_str()))
				{
					pid = process_entry_.th32ProcessID;
					break;
				}
			} while (Process32NextW(hPID, &process_entry_));
		}
		CloseHandle(hPID);
		return pid;
	}
	uint32_t FindProcessIdByWindowName(const char* window_name)
	{
		DWORD process_id = 0;
		HWND windowHandle = FindWindowA(nullptr, window_name);
		if (windowHandle)
			GetWindowThreadProcessId(windowHandle, &process_id);
		return process_id;
	}
	HWND GetWindowHandleFromProcessId(DWORD ProcessId)
	{
		HWND hwnd = NULL;
		do {
			hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);
			if (pid == ProcessId) {
				TCHAR windowTitle[MAX_PATH];
				GetWindowText(hwnd, windowTitle, MAX_PATH);
				if (IsWindowVisible(hwnd) && windowTitle[0] != '\0') {
					return hwnd;
				}
			}
		} while (hwnd != NULL);
		return NULL;
	}
};

class Protections
{
public:
	void RenameFile()
	{
		char buffer[MAX_PATH];
		GetModuleFileNameA(NULL, buffer, MAX_PATH);
		std::string current_path = buffer;
		std::string filename = current_path.substr(current_path.find_last_of(xorstr_("\\/")) + 1);
		static const std::string chars = xorstr_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
		static std::random_device rd;
		static std::mt19937 gen(rd());
		std::uniform_int_distribution<> length_dist(7, 14);
		std::uniform_int_distribution<> char_dist(0, chars.size() - 1);

		int length = length_dist(gen);
		std::string result;
		result.reserve(length);

		for (int i = 0; i < length; ++i) {
			result += chars[char_dist(gen)];
		}
		result += ".exe";
		int sjdhds = std::rename(filename.c_str(), result.c_str());
	}
}; inline Protections protections{};

class Input
{
private:
	static BYTE ntusersendinput_bytes[30];
public:
	bool init()
	{
		LPVOID ntusersendinput_addr = GetProcAddress(librarys::user32, xorstr_("NtUserSendInput"));
		if (!ntusersendinput_addr)
		{
			ntusersendinput_addr = GetProcAddress(librarys::win32u, xorstr_("NtUserSendInput"));
			if (!ntusersendinput_addr) return FALSE;
		}
		memcpy(ntusersendinput_bytes, ntusersendinput_addr, 30);
		return TRUE;
	}
	bool ntusersendinput(UINT cinputs, LPINPUT pinputs, int cbsize)
	{
		LPVOID ntusersendinput_spoof = VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!ntusersendinput_spoof) return false;
		memcpy(ntusersendinput_spoof, ntusersendinput_bytes, 30);
		NTSTATUS result = reinterpret_cast<NTSTATUS(NTAPI*)(UINT, LPINPUT, int)>(ntusersendinput_spoof)(cinputs, pinputs, cbsize);
		ZeroMemory(ntusersendinput_spoof, 0x1000);
		VirtualFree(ntusersendinput_spoof, 0, MEM_RELEASE);
		if (result > 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	bool move_mouse(int x, int y)
	{
		INPUT input = { 0 };
		input.type = INPUT_MOUSE;
		input.mi.mouseData = 0;
		input.mi.time = 0;
		input.mi.dx = x;
		input.mi.dy = y;
		input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_VIRTUALDESK;
		return ntusersendinput(1, &input, sizeof(input));
	}
}; inline Input input{};

namespace banding
{
	typedef HWND(WINAPI* CreateWindowInBand)(_In_ DWORD dwExStyle, _In_opt_ ATOM atom, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam, DWORD band);
	typedef BOOL(WINAPI* GetWindowBand)(HWND hWnd, PDWORD pdwBand);
	typedef BOOL(WINAPI* SetWindowBand)(HWND hWnd, DWORD dwBand);
	CreateWindowInBand create_window_in_band = 0;
	GetWindowBand get_window_band = 0;
	SetWindowBand set_window_band = 0;
	enum ZBID
	{
		ZBID_DEFAULT = 0,
		ZBID_DESKTOP = 1,
		ZBID_UIACCESS = 2,
		ZBID_IMMERSIVE_IHM = 3,
		ZBID_IMMERSIVE_NOTIFICATION = 4,
		ZBID_IMMERSIVE_APPCHROME = 5,
		ZBID_IMMERSIVE_MOGO = 6,
		ZBID_IMMERSIVE_EDGY = 7,
		ZBID_IMMERSIVE_INACTIVEMOBODY = 8,
		ZBID_IMMERSIVE_INACTIVEDOCK = 9,
		ZBID_IMMERSIVE_ACTIVEMOBODY = 10,
		ZBID_IMMERSIVE_ACTIVEDOCK = 11,
		ZBID_IMMERSIVE_BACKGROUND = 12,
		ZBID_IMMERSIVE_SEARCH = 13,
		ZBID_GENUINE_WINDOWS = 14,
		ZBID_IMMERSIVE_RESTRICTED = 15,
		ZBID_SYSTEM_TOOLS = 16,
		// Win10
		ZBID_LOCK = 17,
		ZBID_ABOVELOCK_UX = 18,
	};
	DWORD duplicate_winlogin_token(DWORD session_id, DWORD desired_access, PHANDLE token_phandle)
	{
		DWORD dwerr;
		PRIVILEGE_SET ps;
		ps.PrivilegeCount = 1;
		ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
		if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &ps.Privilege[0].Luid))
		{
			HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (INVALID_HANDLE_VALUE != snapshot_handle)
			{
				BOOL bcont;
				PROCESSENTRY32 pe;
				pe.dwSize = sizeof(pe);
				dwerr = ERROR_NOT_FOUND;
				for (bcont = Process32First(snapshot_handle, &pe); bcont; bcont = Process32Next(snapshot_handle, &pe))
				{
					HANDLE process_handle;
					if (0 != _tcsicmp(pe.szExeFile, TEXT("winlogon.exe"))) continue;
					process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
					if (process_handle)
					{
						HANDLE token_handle;
						DWORD retlen, sid;
						if (OpenProcessToken(process_handle, TOKEN_QUERY | TOKEN_DUPLICATE, &token_handle))
						{
							BOOL ftcb;
							if (PrivilegeCheck(token_handle, &ps, &ftcb) && ftcb)
							{
								if (GetTokenInformation(token_handle, TokenSessionId, &sid, sizeof(sid), &retlen) && sid == session_id)
								{
									if (DuplicateTokenEx(token_handle, desired_access, 0, SecurityImpersonation, TokenImpersonation, token_phandle))
									{
										dwerr = ERROR_SUCCESS;
									}
									else
									{
										dwerr = GetLastError();
									}
									CloseHandle(token_handle);
									CloseHandle(process_handle);
									break;
								}
							}
							CloseHandle(token_handle);
						}
						CloseHandle(process_handle);
					}
				}
				CloseHandle(snapshot_handle);
			}
			else
			{
				dwerr = GetLastError();
			}
		}
		else
		{
			dwerr = GetLastError();
		}
		return dwerr;
	}
	DWORD create_ui_access_token(PHANDLE token_phandle)
	{
		DWORD dwerr;
		HANDLE token_self_handle;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token_self_handle))
		{
			DWORD session_id, retlen;
			if (GetTokenInformation(token_self_handle, TokenSessionId, &session_id, sizeof(session_id), &retlen))
			{
				HANDLE token_system_handle;
				dwerr = duplicate_winlogin_token(session_id, TOKEN_IMPERSONATE, &token_system_handle);
				if (ERROR_SUCCESS == dwerr)
				{
					if (SetThreadToken(NULL, token_system_handle))
					{
						if (DuplicateTokenEx(token_self_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, 0, SecurityAnonymous, TokenPrimary, token_phandle))
						{
							BOOL ui_access = TRUE;
							if (!SetTokenInformation(*token_phandle, TokenUIAccess, &ui_access, sizeof(ui_access)))
							{
								dwerr = GetLastError();
								CloseHandle(*token_phandle);
							}
						}
						else
						{
							dwerr = GetLastError();
						}
						RevertToSelf();
					}
					else
					{
						dwerr = GetLastError();
					}
					CloseHandle(token_system_handle);
				}
			}
			else
			{
				dwerr = GetLastError();
			}
			CloseHandle(token_self_handle);
		}
		else
		{
			dwerr = GetLastError();
		}
		return dwerr;
	}
	BOOL check_for_ui_acces(DWORD* pdwerr, DWORD* ui_access)
	{
		BOOL result = FALSE;
		HANDLE token_handle;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle))
		{
			DWORD retlen;
			if (GetTokenInformation(token_handle, TokenUIAccess, ui_access, sizeof(*ui_access), &retlen))
			{
				result = TRUE;
			}
			else
			{
				*pdwerr = GetLastError();
			}
			CloseHandle(token_handle);
		}
		else
		{
			*pdwerr = GetLastError();
		}
		return result;
	}
	DWORD prepare_for_ui_access()
	{
		DWORD dwerr;
		HANDLE token_ui_access_handle;
		BOOL ui_access;
		if (check_for_ui_acces(&dwerr, (DWORD*)&ui_access))
		{
			if (ui_access)
			{
				dwerr = ERROR_SUCCESS;
			}
			else
			{
				dwerr = create_ui_access_token(&token_ui_access_handle);
				if (ERROR_SUCCESS == dwerr)
				{
					STARTUPINFO si;
					PROCESS_INFORMATION pi;
					GetStartupInfo(&si);

					if (CreateProcessAsUser(token_ui_access_handle, 0, GetCommandLine(), 0, 0, FALSE, 0, 0, 0, &si, &pi))
					{
						system(xorstr_("cls"));
						CloseHandle(pi.hProcess);
						CloseHandle(pi.hThread);
						ExitProcess(0);
					}
					else
					{
						dwerr = GetLastError();
					}
					CloseHandle(token_ui_access_handle);
				}
			}
		}
		return dwerr;
	}
	bool init()
	{
		const DWORD dwerr = prepare_for_ui_access();
		if (ERROR_SUCCESS != dwerr) return false;
		create_window_in_band = reinterpret_cast<CreateWindowInBand>(GetProcAddress(librarys::user32, xorstr_("CreateWindowInBand")));
		if (!create_window_in_band)
		{
			create_window_in_band = reinterpret_cast<CreateWindowInBand>(GetProcAddress(librarys::win32u, xorstr_("CreateWindowInBand")));
			if (!create_window_in_band) return false;
		}
		return true;
	}
}

class Overlay
{
private:
	std::vector<std::thread::id> activeThreadIds;
	std::mutex threadMutex;

	RECT GameRect{};
	POINT GamePoint{};

	WNDCLASSEXW wc = {};

	ID3D11Device* g_pd3dDevice = nullptr;
	ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
	IDXGISwapChain* g_pSwapChain = nullptr;
	ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

	float m_fps = 0.0f;
	float m_fps_update_time = 0.0f;
	float m_fps_frame_count = 0;
public:
	void start_background_thread(std::function<void()> func) {
		std::thread t([func]() {
			func();
			});

		{
			std::lock_guard<std::mutex> lock(threadMutex);
			activeThreadIds.push_back(t.get_id());
		}

		t.detach();
	}
	class Gui
	{
	public:
		HWND game_window = nullptr;
		HWND athena_overlay = nullptr;
		bool quit = false;
		bool showmenu = true;

		int width = GetSystemMetrics(SM_CXSCREEN);
		int height = GetSystemMetrics(SM_CYSCREEN);

		bool streamproof = true;
		bool vsync = true;

		void bring_window_front(HWND hwnd)
		{
			if (IsIconic(hwnd)) {
				ShowWindow(hwnd, SW_RESTORE);
			}

			SetForegroundWindow(hwnd);
			SetActiveWindow(hwnd);
			SetFocus(hwnd);
		}

		void set_next_window(float size_ratio)
		{
			float w = width * size_ratio;
			float h = height * size_ratio;

			ImVec2 window_size(w, h);
			ImVec2 window_pos((width - w) * 0.5f, (height - h) * 0.5f);

			ImGui::SetNextWindowSize(window_size, ImGuiCond_Always);
			ImGui::SetNextWindowPos(window_pos, ImGuiCond_Always);
		}

		void tooltip(const char* text) {
			if (ImGui::IsItemHovered()) {
				ImGui::BeginTooltip(); {
					ImGui::Text(text);
				}ImGui::EndTooltip();
			}
		}

		void center_text(const char* text)
		{
			ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ImGui::CalcTextSize(text).x) * 0.5f);
			ImGui::Text(text);
		}

		bool center_input_text(const char* title, const char* label, char* buf, size_t buf_size, ImGuiInputTextFlags flags = 0, ImGuiInputTextCallback callback = NULL, void* user_data = NULL) {
			const float input_width = ImGui::CalcItemWidth();
			ImGui::SetCursorPosX((ImGui::GetWindowContentRegionMax().x - input_width) / 2.f);
			ImGui::Text(xorstr_("%s"), title);
			ImGui::SetCursorPosX((ImGui::GetWindowContentRegionMax().x - input_width) / 2.f);
			return ImGui::InputText(label, buf, buf_size, flags, callback, user_data);
		}

		void spacer()
		{
			ImGui::Dummy(ImVec2(0, 10));
		}
	}; Gui gui{};

	float get_fps() const { return m_fps; }

	void wait_for_game_load()
	{
		while (!gui.game_window)
		{
			gui.game_window = FindWindow(xorstr_(L"SDL_app"), xorstr_(L"Counter-Strike 2"));
			Sleep(1);
		}

		if (IsIconic(gui.game_window)) {
			ShowWindow(gui.game_window, SW_RESTORE);
		}

		SetForegroundWindow(gui.game_window);
		SetActiveWindow(gui.game_window);
		SetFocus(gui.game_window);
	}

	void create_overlay()
	{
		int x = 0, y = 0, w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
		if (GetWindowRect(gui.game_window, &GameRect))
		{
			x = GameRect.left;
			y = GameRect.top;
			w = GameRect.right - GameRect.left;
			h = GameRect.bottom - GameRect.top;
		}
		else
		{
			logger.error(xorstr_("Failed GetWindowRect"));
		}

		wc.cbSize = sizeof(wc);
		wc.style = CS_CLASSDC;
		wc.lpfnWndProc = WndProc;
		wc.hInstance = GetModuleHandle(nullptr);
		wc.lpszClassName = xorstr_(L"AthenaOverlayClass");

		ATOM res = RegisterClassExW(&wc);
		if (!res)
		{
			logger.error(xorstr_("Failed RegisterClassExW"));
		}

		if (!banding::init())
		{
			logger.error(xorstr_("Failed to initialize overlay dependencies"));
		}
		gui.athena_overlay = banding::create_window_in_band(0, res, xorstr_(L"AthenaOverlay"), WS_POPUP, GameRect.left, GameRect.top, GameRect.right, GameRect.bottom, 0, 0, wc.hInstance, 0, banding::ZBID_UIACCESS);

		if (!gui.athena_overlay)
		{
			UnregisterClass(wc.lpszClassName, wc.hInstance);
			logger.error(xorstr_("Failed to create overlay"));
		}

		SetLayeredWindowAttributes(gui.athena_overlay, RGB(0, 0, 0), 255, LWA_ALPHA);
		MARGINS margin = { -1 };
		DwmExtendFrameIntoClientArea(gui.athena_overlay, &margin);

		DXGI_SWAP_CHAIN_DESC sd;
		ZeroMemory(&sd, sizeof(sd));
		sd.BufferCount = 2;
		sd.BufferDesc.Width = 0;
		sd.BufferDesc.Height = 0;
		sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		sd.BufferDesc.RefreshRate.Numerator = 60;
		sd.BufferDesc.RefreshRate.Denominator = 1;
		sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		sd.OutputWindow = gui.athena_overlay;
		sd.SampleDesc.Count = 1;
		sd.SampleDesc.Quality = 0;
		sd.Windowed = TRUE;
		sd.SwapEffect = DXGI_SWAP_EFFECT_SEQUENTIAL;

		UINT createDeviceFlags = 0;
		D3D_FEATURE_LEVEL featureLevel;
		const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
		HRESULT result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
		if (result == DXGI_ERROR_UNSUPPORTED)
			result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
		if (result != S_OK)
		{
			if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
			if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
			if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
			if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
			UnregisterClass(wc.lpszClassName, wc.hInstance);
			logger.error(xorstr_("Failed CreateDeviceD3D"));
		}

		ID3D11Texture2D* pBackBuffer;
		g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
		if (!pBackBuffer)
		{
			if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
			if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
			if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
			if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
			UnregisterClass(wc.lpszClassName, wc.hInstance);
			logger.error(xorstr_("Failed to get pBackBuffer"));
		}
		g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
		pBackBuffer->Release();

		ShowWindow(gui.athena_overlay, SW_SHOWDEFAULT);
		UpdateWindow(gui.athena_overlay);
	}

	void setup_imgui()
	{
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO(); (void)io;
		io.IniFilename = nullptr;
		io.LogFilename = nullptr;
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_NavEnableGamepad;

		ImGui::StyleColorsDark();

		ImGui_ImplWin32_Init(gui.athena_overlay);
		ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
	}

	void start_render()
	{
		if (GetAsyncKeyState(VK_INSERT) & 1) {
			gui.showmenu = !gui.showmenu;
		}

		if (GetAsyncKeyState(VK_END) & 1) {
			shutdown();
		}

		MSG msg;
		while (::PeekMessage(&msg, gui.athena_overlay, 0U, 0U, PM_REMOVE)) {
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);

			if (msg.message == WM_QUIT) {
				gui.quit = true;
				break;
			}
		}


		if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
			if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
			g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
			g_ResizeWidth = g_ResizeHeight = 0;
			ID3D11Texture2D* pBackBuffer;
			g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
			g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
			pBackBuffer->Release();
		}

		HWND foreground_window = GetForegroundWindow();
		if (!(foreground_window == gui.athena_overlay || foreground_window == gui.game_window)) {
			Sleep(16);
		}

		RECT TmpRect{};
		POINT TmpPoint{};
		GetClientRect(gui.game_window, &TmpRect);
		ClientToScreen(gui.game_window, &TmpPoint);

		if (TmpRect.left != GameRect.left || TmpRect.bottom != GameRect.bottom ||
			TmpRect.top != GameRect.top || TmpRect.right != GameRect.right ||
			TmpPoint.x != GamePoint.x || TmpPoint.y != GamePoint.y) {
			GameRect = TmpRect;
			GamePoint = TmpPoint;

			HWND hwnd_above = GetWindow(gui.game_window, GW_HWNDPREV);
			SetWindowPos(gui.athena_overlay, hwnd_above, TmpPoint.x, TmpPoint.y, GameRect.right - GameRect.left, GameRect.bottom - GameRect.top, SWP_NOREDRAW);
		}

		SetWindowPos(gui.athena_overlay, (foreground_window == gui.game_window) ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetWindowLong(gui.athena_overlay, GWL_EXSTYLE, gui.showmenu ? WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | ((foreground_window == gui.game_window) ? WS_EX_TOPMOST : 0) : WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW);


		m_fps_frame_count++;
		float current_time = (float)ImGui::GetTime();
		if (current_time - m_fps_update_time >= 1.0f) {
			m_fps = m_fps_frame_count;
			m_fps_frame_count = 0;
			m_fps_update_time = current_time;
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		SetWindowDisplayAffinity(gui.athena_overlay, gui.streamproof ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
	}

	void show_watermark(std::string text, int r, int g, int b, int a)
	{
		ImGui::GetBackgroundDrawList()->AddText(ImVec2(GameRect.left + 10, GameRect.top + 10), ImColor(r, g, b, a), text.c_str());
	}
	void end_render()
	{
		ImGui::Render();
		ImVec4 clear_color = ImVec4(0.f, 0.f, 0.f, 0.f);
		const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
		g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
		g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		g_pSwapChain->Present(gui.vsync ? 1 : 0, 0x00000100UL);
	}

	void shutdown()
	{
		ImGui_ImplDX11_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();

		if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
		if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
		if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
		if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
		UnregisterClass(wc.lpszClassName, wc.hInstance);
		exit(0);
	}
}; inline Overlay overlay{};

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {

	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
		return true;
	}

	switch (msg) {
	case WM_SIZE:
		if (wParam == SIZE_MINIMIZED)
			return 0;
		g_ResizeWidth = (UINT)LOWORD(lParam);
		g_ResizeHeight = (UINT)HIWORD(lParam);
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU)
			return 0;
		break;
	case WM_DESTROY:
		::PostQuitMessage(0);
		return 0;
	}

	return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}