import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Pplblade : FILE
{
	meta:
		description = "Detects PPLBlade Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk"
		author = "ditekSHen"
		id = "60c9b036-51a0-5e08-83de-1f69f62245c3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1698-L1722"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "da21402b07fcd0358ba630e48ab35956cb7ed8c12836a339c85b2ee5e414543e"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "PPLBlade" ascii
		$x2 = "/PPLBlade/" ascii
		$x3 = "PPLBlade.exe --mode" ascii
		$x4 = "PPLBLADE.SYSPPLBlade.dmp" ascii
		$s1 = "Dump bytes sent at %s:%d. Protocol: %s" ascii
		$s2 = "Deobfuscated dump saved in file %s" ascii
		$m1 = "main.WriteDriverOnDisk" ascii
		$m2 = "main.ProcExpOpenProc" ascii
		$m3 = "main.miniDumpCallback" ascii
		$m4 = "main.copyDumpBytes" ascii
		$m5 = "main.MiniDumpGetBytes" ascii
		$m6 = "main.SendBytesRaw" ascii
		$m7 = "main.SendBytesSMB" ascii
		$m8 = "main.DeobfuscateDump" ascii
		$m9 = "main.dumpMutex" ascii
		$m10 = "main.dbghelpDLL" ascii
		$m11 = "main.miniDumpWriteDump" ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($x*) or (1 of ($x*) and (1 of ($s*) or 3 of ($m*))) or ( all of ($s*) and 3 of ($m*)) or (7 of ($m*)))
}