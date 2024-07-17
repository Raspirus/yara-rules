
rule SIGNATURE_BASE_Chafer_Packed_Mimikatz : FILE
{
	meta:
		description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
		author = "Florian Roth (Nextron Systems) / Markus Neis"
		id = "abd34c6a-7d99-5f52-be8e-a7d634d61255"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_chafer_mar18.yar#L78-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0cee5270c9b76f1419c6989113dca221c5ba6f027a104d71f61d38cb59af51cd"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"

	strings:
		$s1 = "Windows Security Credentials" fullword wide
		$s2 = "Minisoft" fullword wide
		$x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and ( all of ($s*) or $x1)
}