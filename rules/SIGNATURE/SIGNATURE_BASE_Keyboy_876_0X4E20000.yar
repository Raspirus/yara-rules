rule SIGNATURE_BASE_Keyboy_876_0X4E20000 : FILE
{
	meta:
		description = "Detects KeyBoy Backdoor"
		author = "Markus Neis, Florian Roth"
		id = "0b871f62-0f7c-5c94-9b3d-f68832ab64b4"
		date = "2018-03-26"
		modified = "2023-12-05"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_keyboys.yar#L128-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "092bb19cd7a4250560ea71a3e54780a8fd34a229caa294e4cd5b6d522850d519"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "6e900e5b6dc4f21a004c5b5908c81f055db0d7026b3c5e105708586f85d3e334"

	strings:
		$x1 = "%s\\rundll32.exe %s ServiceTake %s %s" fullword ascii
		$x2 = "#%sCmd shell is not running,or your cmd is error!" fullword ascii
		$x3 = "Take Screen Error,May no user login!" fullword ascii
		$x4 = "Get logon user fail!" fullword ascii
		$x5 = "8. LoginPasswd:%s" fullword ascii
		$x6 = "Take Screen Error,service dll not exists" fullword ascii
		$s1 = "taskkill /f /pid %s" fullword ascii
		$s2 = "TClient.exe" fullword ascii
		$s3 = "%s\\wab32res.dll" fullword ascii
		$s4 = "%s\\rasauto.dll" fullword ascii
		$s5 = "Download file:%s index:%d" fullword ascii
		$s6 = "LogonUser: [%s]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or 3 of them )
}