rule SIGNATURE_BASE_Freemilk_APT_Mal_3 : FILE
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "152781f0-756b-50ab-b588-4af5fa4ce419"
		date = "2017-10-05"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_freemilk.yar#L62-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "be68f624a2a374525857193d27f0645be5d10c198954dd90350448c3127e4bb5"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ef40f7ddff404d1193e025081780e32f88883fa4dd496f4189084d772a435cb2"

	strings:
		$s1 = "CMD.EXE /C \"%s\"" fullword wide
		$s2 = "\\command\\start.exe" wide
		$s3 = ".bat;.com;.cmd;.exe" fullword wide
		$s4 = "Unexpected failure opening HKCR key: %d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and all of them )
}