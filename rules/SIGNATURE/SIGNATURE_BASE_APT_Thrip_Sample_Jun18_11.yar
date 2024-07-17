import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_11 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "69476f7d-c436-5863-bf20-1d3e821974e6"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L191-L210"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "066fc3622a0db5cc511e85f6efc08191c2c9268524c8761dc17a05e6d133c263"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "590a6796b97469f8e6977832a63c0964464901f075a9651f7f1b4578e55bd8c8"

	strings:
		$s1 = "\\AppData\\Local\\Temp\\dw20.EXE" ascii
		$s2 = "C:\\Windows\\system32\\sysprep\\cryptbase.dll" fullword ascii
		$s3 = "WFQNJMBWF" fullword ascii
		$s4 = "SQLWLWZSF" fullword ascii
		$s5 = "PFQUFQSBPP" fullword ascii
		$s6 = "WQZXQFPVOW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="6eef4394490378f32d134ab3bf4bf194" or all of them )
}