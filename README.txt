
===========================================
      Phantom IIS Reflective Loader
===========================================

Phantom is project created to perform loading and executing .NET assemblies directly in memory within an IIS environment running in full‑trust mode. Instead of relying on  file‑based approach, it uses reflective loading techniques to inject and run a DLL inside the memory space of the w3wp.exe worker pool process. The project is composed of two primary parts:


===========================================
        1      Phantom (ASPX) 
===========================================

Phantom/
├── v1/
└── v2/

An ASPX-based loader that incorporates various evasion‑oriented techniques to dynamically load a .NET assembly into memory and execute it without writing the DLL to disk. Its purpose is to provide an in‑memory execution pathway within the IIS application context.

===========================================
        2      PhantomLink .NET
===========================================

PhantomLink/
├── PhantomLink.cs
└── PhantomLink.csproj
└── PhantomLink.sln
└── README

A .NET assembly is designed to work alongside the Phantom loader. it's primary objective is to be used with command‑and‑control (c2) framework. PhantomLinker allows C2's operators to connect into Phantom loader and leverage it's functionality to execute a DLL completely from the C2 itself. it is a great way to perform lateral movement or persistence. 



===========================================
       3     Publications 
===========================================

Official blogpost : https://www.resillion.com/blogs/when-trusted-infrastructure-becomes-the-attack-surface/ 
Official full paper: https://www.resillion.com/resources/when-internet-information-services-iis-becomes-a-lateral-movement-platform/
