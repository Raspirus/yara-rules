
rule SIGNATURE_BASE_SUSP_Modified_Systemexefilename_In_File : FILE
{
	meta:
		description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
		author = "Florian Roth (Nextron Systems)"
		id = "97d91e1b-49b8-504e-9e9c-6cfb7c2afe41"
		date = "2018-12-11"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L234-L248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "45c01024c4e6a3563cd27d8a78e2236d49aa795d24f322774a14b4c7289830c4"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
		hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"

	strings:
		$s1 = "svchosts.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 1 of them
}