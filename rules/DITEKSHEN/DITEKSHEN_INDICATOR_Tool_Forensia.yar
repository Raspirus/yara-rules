import "pe"


rule DITEKSHEN_INDICATOR_Tool_Forensia : FILE
{
	meta:
		description = "Detects Forensia anti-forensics tool used for erasing footprints"
		author = "ditekSHen"
		id = "bcd05c2e-7ddd-5ce7-a6a7-0659bed38744"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1490-L1523"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "7147eee62df10cd8a6c00ec80c4d1bdb8234a181dd6af81d0580d847f05bd0b6"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$c1 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" ascii
		$c2 = "del /F /Q C:\\Windows\\Prefetch\\*" ascii
		$c3 = "del C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf" ascii
		$c4 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\*" ascii
		$c5 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*" ascii
		$c6 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*" ascii
		$c7 = "fsutil.exe usn deletejournal /D C:" ascii
		$r1 = "\\Memory Management\\PrefetchParameters" wide
		$r2 = "\\Explorer\\Advanced" wide
		$r3 = "\\Services\\EventLog" wide
		$r4 = "\\Shell\\BagMRU" wide
		$r5 = "\\Control\\FileSystem" wide
		$r6 = "\\Setup\\VC" wide
		$s1 = "[LOG] - %s" wide
		$s2 = "\\forensia\\regedit.hpp" wide
		$s3 = "NtfsDisableLastAccessUpdate" wide
		$s4 = "Melting The Executable" wide
		$s5 = "Sysmon Unloader" wide
		$s6 = "Rundll32.exe apphelp.dll,ShimFlushCache" ascii
		$s7 = "\\Debug\\forensia.pdb" ascii
		$s8 = { 55 00 00 00 aa 00 00 00 92 49 24 00 49 24 92 00
                24 92 49 00 00 00 00 00 11 00 00 00 22 00 00 00
                33 00 00 00 44 00 00 00 66 00 00 00 88 00 00 00
                99 00 00 00 bb 00 00 00 cc 00 00 00 dd 00 00 00
                ee 00 00 00 ff 00 00 00 6d b6 db 00 b6 db 6d 00
                db 6d b6 }

	condition:
		uint16(0)==0x5a4d and ((4 of ($c*) and 2 of ($r*)) or (4 of ($r*) and 2 of ($c*)) or 6 of ($s*) or (3 of ($s*) and 2 of ($r*) and 1 of ($c*)))
}