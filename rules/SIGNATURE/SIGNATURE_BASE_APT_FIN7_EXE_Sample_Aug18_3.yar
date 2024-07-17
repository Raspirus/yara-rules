rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_3 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "0b0ce882-1c18-5741-bb71-0cef010dc778"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L126-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3f757bc4a6d46be85732fe33dd0a323c5774cbc1f0da2b984c5db14c1362745a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"

	strings:
		$s1 = "cvzdfhtjkdhbfszngjdng" fullword ascii
		$s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <50KB and 1 of them
}