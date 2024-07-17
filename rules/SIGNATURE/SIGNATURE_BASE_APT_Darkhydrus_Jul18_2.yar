rule SIGNATURE_BASE_APT_Darkhydrus_Jul18_2 : FILE
{
	meta:
		description = "Detects strings found in malware samples in APT report in DarkHydrus"
		author = "Florian Roth (Nextron Systems)"
		id = "1a21cbbf-f7e1-56eb-973b-35c1a811e210"
		date = "2018-07-28"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_darkhydrus.yar#L31-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e967fec69ad1cbb46a63ee520594e7d6f2445a400510a9864dbd6d4c6e092737"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b2571e3b4afbce56da8faa726b726eb465f2e5e5ed74cf3b172b5dd80460ad81"

	strings:
		$s4 = "windir" fullword ascii
		$s6 = "temp.dll" fullword ascii
		$s7 = "libgcj-12.dll" fullword ascii
		$s8 = "%s\\System32\\%s" fullword ascii
		$s9 = "StartW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of them
}