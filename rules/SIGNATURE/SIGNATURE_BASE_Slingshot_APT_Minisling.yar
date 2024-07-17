import "pe"


rule SIGNATURE_BASE_Slingshot_APT_Minisling : FILE
{
	meta:
		description = "Detects malware from Slingshot APT"
		author = "Florian Roth (Nextron Systems)"
		id = "99f9d5a1-b29f-52f7-9aec-02df4a51a756"
		date = "2018-03-09"
		modified = "2023-12-05"
		reference = "https://securelist.com/apt-slingshot/84312/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_slingshot.yar#L26-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7d370271fea6c607c051eb49681600b4f59878c2fd2d43d71194bddda78d7b09"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}