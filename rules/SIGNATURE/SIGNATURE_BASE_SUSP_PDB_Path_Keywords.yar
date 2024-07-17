rule SIGNATURE_BASE_SUSP_PDB_Path_Keywords : FILE
{
	meta:
		description = "Detects suspicious PDB paths"
		author = "Florian Roth (Nextron Systems)"
		id = "cbd9b331-58bb-5b29-88a2-5c19f12893a9"
		date = "2019-10-04"
		modified = "2023-12-05"
		reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L359-L385"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "274b4b40190b8f7e3d123fad63e2bb6b2114a3dbef062791d442109cac149b08"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$ = "Debug\\Shellcode" ascii
		$ = "Release\\Shellcode" ascii
		$ = "Debug\\ShellCode" ascii
		$ = "Release\\ShellCode" ascii
		$ = "Debug\\shellcode" ascii
		$ = "Release\\shellcode" ascii
		$ = "shellcode.pdb" nocase ascii
		$ = "\\ShellcodeLauncher" ascii
		$ = "\\ShellCodeLauncher" ascii
		$ = "Fucker.pdb" ascii
		$ = "\\AVFucker\\" ascii
		$ = "ratTest.pdb" ascii
		$ = "Debug\\CVE_" ascii
		$ = "Release\\CVE_" ascii
		$ = "Debug\\cve_" ascii
		$ = "Release\\cve_" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}