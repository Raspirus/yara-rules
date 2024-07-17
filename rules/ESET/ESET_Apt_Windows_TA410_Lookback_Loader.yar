rule ESET_Apt_Windows_TA410_Lookback_Loader : FILE
{
	meta:
		description = "Matches the modified function in LookBack libcurl loader."
		author = "ESET Research"
		id = "d0aac4f6-f72f-5adf-8f8f-9251bad70131"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L256-L309"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "98390dd664227ad747e5572771d12e7ebd2475d26db27e85508347ac6f44f3bf"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530e0]
            6A 40          //push 0x40
            68 00 10 00 00     //push 0x1000
            68 F0 04 00 00     //push 0x4f0
            6A 00          //push 0
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530d4]
            8B E8          //mov ebp, eax
            B9 3C 01 00 00     //mov ecx, 0x13c
            BE 60 30 06 10     //mov esi, 0x10063060
            8B FD          //mov edi, ebp
            68 F0 04 00 00     //push 0x4f0
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            55             //push ebp
            E8 ?? ?? ?? ??     //call 0x100258d0
            8B 0D ?? ?? ?? ??      //mov ecx, dword ptr [0x100530e4]
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x100530c8]
            68 6C 02 00 00     //push 0x26c
            89 4C 24 ??        //mov dword ptr [esp + 0x1c], ecx
            89 44 24 ??        //mov dword ptr [esp + 0x20], eax
            FF 15 ?? ?? ?? ??      //call dword ptr [0x10063038]
            8B D8          //mov ebx, eax
            B9 9B 00 00 00     //mov ecx, 0x9b
            BE 50 35 06 10     //mov esi, 0x10063550
            8B FB          //mov edi, ebx
            68 6C 02 00 00      //push 0x26c
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            53             //push ebx
            E8 ?? ?? ?? ??     //call 0x100258d0
            83 C4 14           //add esp, 0x14
            8D 44 24 ??        //lea eax, [esp + 0x10]
            50             //push eax
            53             //push ebx
            8D 44 24 ??        //lea eax, [esp + 0x3c]
            50             //push eax
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x10063058]
            FF 74 24 ??        //push dword ptr [esp + 0x28]
            03 C5          //add eax, ebp
            FF D0          //call eax
        }

	condition:
		uint16(0)==0x5a4d and all of them
}