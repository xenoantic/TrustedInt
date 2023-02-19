using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.ServiceProcess;
using System.Security.Principal;


namespace TrustedInt
{
    internal class Functions
    { 
        //<<<<<<<<<<<<<<<<<<<<<<<<<<<DLLIMPORTS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        // P/Invoke signature for closing a handle
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // P/Invoke signature for opening the process token
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        // P/Invoke signature for looking up a privilege value
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        // P/Invoke signature for adjusting a token's privileges
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPrivLuid newst, int len, IntPtr prev, IntPtr relen);

        // P/Invoke signature for opening a process token
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        // P/Invoke signature for impersonating a user
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        // P/Invoke signature for opening the service control manager
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        // P/Invoke signature for opening a service
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        // P/Invoke signature for querying the service status
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceStatusEx(IntPtr hService, int InfoLevel, ref SERVICE_STATUS_PROCESS lpBuffer, uint cbBufSize, out uint pcbBytesNeeded);

        // P/Invoke signature for starting a service
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

        // P/Invoke signature for closing a service handle
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);
     
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetUserName(System.Text.StringBuilder sb, ref Int32 length);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<DLLIMPORTS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


        //<<<<<<<<<<<<<<<<<<<<<<<<<<<CONSTANTS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        // Constants for token access and privilege attributes
        const int TOKEN_QUERY = 0x0008;
        const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const int SE_PRIVILEGE_ENABLED = 0x00000002;

        // Constants for process access and token attributes
        const uint MAXIMUM_ALLOWED = 0x02000000;

        // Constants for service access
        const uint SC_MANAGER_CONNECT = 0x0001;
        const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        const uint SC_MANAGER_QUERY_LOCK_STATUS = 0x0010;
        const uint SERVICE_QUERY_STATUS = 0x0004;
        const uint SERVICE_START = 0x0010;
        const int SC_STATUS_PROCESS_INFO = 0;
        const string ServicesActiveDatabase = "ServicesActive";

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<CONSTANTS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



        //<<<<<<<<<<<<<<<<<<<<<<<<<<<STRUCTURES>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        // Structure for security attributes
        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        // Structure for service status
        [StructLayout(LayoutKind.Sequential)]
        struct SERVICE_STATUS_PROCESS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
            public uint dwProcessId;
            public uint dwServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TokPrivLuid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        //<<<<<<<<<<<<<<<<<<<<<<<<<<<STRUCTURES>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<FLAGS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<FLAGS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        //<<<<<<<<<<<<<<<<<<<<<<<<<<<METHODS>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

        public static bool CheckIfAdmin()
        {
            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
            WindowsPrincipal currentPrincipal = new WindowsPrincipal(currentIdentity);
            return currentPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        public static bool EnablePrivilege(string privileges)
        {
            bool retVal;
            TokPrivLuid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privileges, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine(privileges + " enabled: " + retVal);
            return true;
        }
        public static void GetUsername()
        {
            StringBuilder Buffer = new StringBuilder(64);
            int nSize = 64;
            GetUserName(Buffer, ref nSize);
            Console.WriteLine(Buffer.ToString());
        }
        public static bool ImpersonateSystem()
        {
            //impersonate using winlogon.exe SYSTEM token
            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;

            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "winlogon")
                {
                    bool token = OpenProcessToken(theProcess.Handle, MAXIMUM_ALLOWED, out tokenHandle);
                    if (!token)
                    {
                        return false;
                    }
                    else
                    {
                        token = ImpersonateLoggedOnUser(tokenHandle);
                        Console.Write("User after impersonation: ");
                        GetUsername();
                        CloseHandle(theProcess.Handle);
                        CloseHandle(tokenHandle);
                        return true;
                    }
                }
            }
            CloseHandle(tokenHandle);
            return false;
        }
        public static int StartTrustedInstallerService()
        {
            IntPtr hSCManager = OpenSCManager(null, ServicesActiveDatabase, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS);
            if (hSCManager == IntPtr.Zero)
            {
                throw new Win32Exception("OpenSCManager failed: " + Marshal.GetLastWin32Error());
            }

            IntPtr hService = OpenService(hSCManager, "TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
            if (hService == IntPtr.Zero)
            {
                CloseServiceHandle(hSCManager);
                throw new Win32Exception("OpenService failed: " + Marshal.GetLastWin32Error());
            }

            uint bytesNeeded;
            SERVICE_STATUS_PROCESS statusBuffer = new SERVICE_STATUS_PROCESS();
            while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, ref statusBuffer, (uint)Marshal.SizeOf(statusBuffer), out bytesNeeded))
            {
                if (statusBuffer.dwCurrentState == (uint)ServiceControllerStatus.Stopped)
                {
                    if (!StartService(hService, 0, IntPtr.Zero))
                    {
                        CloseServiceHandle(hService);
                        CloseServiceHandle(hSCManager);
                        throw new Win32Exception("StartService failed: " + Marshal.GetLastWin32Error());
                    }
                }
                if (statusBuffer.dwCurrentState == (uint)ServiceControllerStatus.StartPending || statusBuffer.dwCurrentState == (uint)ServiceControllerStatus.StopPending)
                {
                    System.Threading.Thread.Sleep((int)statusBuffer.dwWaitHint);
                    continue;
                }
                if (statusBuffer.dwCurrentState == (uint)ServiceControllerStatus.Running)
                {
                    CloseServiceHandle(hService);
                    CloseServiceHandle(hSCManager);
                    return (int)statusBuffer.dwProcessId;
                }
            }

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            throw new Win32Exception("QueryServiceStatusEx failed: " + Marshal.GetLastWin32Error());
        }
        public static void CreateProcessAsTrustedInstaller(int parentProcessId, string binaryPath)
        {
            EnablePrivilege("SeDebugPrivilege");
            EnablePrivilege("SeImpersonatePrivilege");
            ImpersonateSystem();

            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_NEW_CONSOLE = 0x00000010;

            var pInfo = new PROCESS_INFORMATION();
            var siEx = new STARTUPINFOEX();

            IntPtr lpValueProc = IntPtr.Zero;
            IntPtr hSourceProcessHandle = IntPtr.Zero;
            var lpSize = IntPtr.Zero;

            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);

            IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);

            lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValueProc, parentHandle);

            UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            var ps = new SECURITY_ATTRIBUTES();
            var ts = new SECURITY_ATTRIBUTES();
            ps.nLength = Marshal.SizeOf(ps);
            ts.nLength = Marshal.SizeOf(ts);

            // lpCommandLine was used instead of lpApplicationName to allow for arguments to be passed
            bool ret = CreateProcess(null, binaryPath, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref siEx, out pInfo);

            String stringPid = pInfo.dwProcessId.ToString();

        }

    }
}
