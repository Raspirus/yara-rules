import "pe"


rule SIGNATURE_BASE_Bronzebutler_Uacbypass_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "01853352-58fc-56a3-8c20-08405c71e251"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L95-L113"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "64b70b9f5963be9009025c14a6e98be9642599af5226f77946b6255116fc22d8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"

	strings:
		$x1 = "\\Release\\BypassUacDll.pdb" ascii
		$x2 = "%programfiles%internet exploreriexplore.exe" fullword wide
		$x3 = "Elevation:Administrator!new:{3ad055" fullword wide
		$x4 = "BypassUac.pdb" fullword ascii
		$x5 = "[bypassUAC] started X64" fullword wide
		$x6 = "[bypassUAC] started X86" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 1 of them )
}