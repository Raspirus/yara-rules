import "pe"


rule SIGNATURE_BASE_APT17_Unsigned_Symantec_Binary_EFA : FILE
{
	meta:
		description = "Detects APT17 malware"
		author = "Florian Roth (Nextron Systems)"
		id = "56eec517-8b00-5cb5-9806-249e50f53b99"
		date = "2017-10-03"
		modified = "2023-12-05"
		reference = "https://goo.gl/puVc9q"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt17_mal_sep17.yar#L61-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7306c8ae2be4dbf56957e11d78ba85bcfa1c8570ba41f749ea5b0e2a05e9df7b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "128aca58be325174f0220bd7ca6030e4e206b4378796e82da460055733bb6f4f"

	strings:
		$s1 = "Copyright (c) 2007 - 2011 Symantec Corporation" fullword wide
		$s2 = "\\\\.\\SYMEFA" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them and pe.number_of_signatures==0)
}