rule DITEKSHEN_INDICATOR_TOOLS_Edrsandblast : FILE
{
	meta:
		description = "Detects EDRSandBlast"
		author = "ditekShen"
		id = "85d6d82b-a30e-5c79-93e7-8a3bbbf4a403"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1809-L1831"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9b801f053e42fbd646cf62fecf6cbf5f2cceeec82bed93ecd8625984eccb08c6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "credguard" fullword wide
		$s2 = "\\cmd.exe" fullword wide
		$s3 = "ci_%s.dll" fullword wide
		$s4 = "cmd /c sc" wide
		$s5 = "fltmgr_%s.sys" fullword wide
		$s6 = "ntoskrnl_%s.exe" fullword wide
		$s7 = "ProductDir" fullword wide
		$s8 = "lsass.exe" fullword wide
		$s9 = "0x%p;%ws;%ws;;;" ascii
		$s10 = "MiniDumpWriteDump" ascii
		$s11 = "EDRSB_Init: %u" ascii
		$s12 = "ntoskrnloffsets.csv" fullword wide nocase
		$s13 = "wdigestoffsets.csv" fullword wide nocase
		$o1 = { eb 0e 8b 85 34 15 00 00 ff c0 89 85 34 15 00 00 }
		$o2 = { 74 48 8b 85 34 15 00 00 41 b9 04 01 00 00 4c 8d }

	condition:
		uint16(0)==0x5a4d and 7 of them
}