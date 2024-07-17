rule SIGNATURE_BASE_MAL_Backdoor_Win_C3_1 : FILE
{
	meta:
		description = "Detection to identify the Custom Command and Control (C3) binaries."
		author = "FireEye"
		id = "60eb022e-6f4e-5c7d-9ddf-b458a593071e"
		date = "2021-05-11"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ransom_darkside.yar#L58-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "7cdac4b82a7573ae825e5edb48f80be5"
		logic_hash = "369c54b9426edb449004466d30e1010ecefe8cfbea106306eb8eb90b27610dbf"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$dropboxAPI = "Dropbox-API-Arg"
		$knownDLLs1 = "WINHTTP.dll" fullword
		$knownDLLs2 = "SHLWAPI.dll" fullword
		$knownDLLs3 = "NETAPI32.dll" fullword
		$knownDLLs4 = "ODBC32.dll" fullword
		$tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
		$tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
		$tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }

	condition:
		filesize <5MB and uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and ((( all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or ( all of ($tokenString*)))
}