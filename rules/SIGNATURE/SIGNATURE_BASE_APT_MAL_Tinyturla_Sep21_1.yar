import "pe"


rule SIGNATURE_BASE_APT_MAL_Tinyturla_Sep21_1 : FILE
{
	meta:
		description = "Detects Tiny Turla backdoor DLL"
		author = "Cisco Talos"
		id = "19659ac7-310a-52dd-a94c-022c7add752b"
		date = "2021-09-21"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L275-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ede598374bc4a8a870aa29498be4200b4a3d7b289dfcb680fb3f91108d212bca"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"

	strings:
		$a = "Title: " fullword wide
		$b = "Hosts" fullword wide
		$c = "Security" fullword wide
		$d = "TimeLong" fullword wide
		$e = "TimeShort" fullword wide
		$f = "MachineGuid" fullword wide
		$g = "POST" fullword wide
		$h = "WinHttpSetOption" fullword ascii
		$i = "WinHttpQueryDataAvailable" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <25KB and all of them
}