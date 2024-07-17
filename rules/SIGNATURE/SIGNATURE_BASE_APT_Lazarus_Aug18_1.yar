import "pe"


rule SIGNATURE_BASE_APT_Lazarus_Aug18_1 : FILE
{
	meta:
		description = "Detects Lazarus Group Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "fda4970a-2787-5e9c-9944-a6222145f4a7"
		date = "2018-08-24"
		modified = "2023-12-05"
		reference = "https://securelist.com/operation-applejeus/87553/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_applejeus.yar#L39-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "efd43e2d84ba964e7fc7e6c03eaba3dd5181c9cbe51b4a06a7a723dca95fab17"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ef400d73c6920ac811af401259e376458b498eb0084631386136747dfc3dcfa8"
		hash2 = "1b8d3e69fc214cb7a08bef3c00124717f4b4d7fd6be65f2829e9fd337fc7c03c"

	strings:
		$s1 = "mws2_32.dll" fullword wide
		$s2 = "%s.bat" fullword wide
		$s3 = "%s%s%s \"%s > %s 2>&1\"" fullword wide
		$s4 = "Microsoft Corporation. All rights reserved." fullword wide
		$s5 = "ping 127.0.0.1 -n 3" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="3af996e4f960108533e69b9033503f40" or 4 of them )
}