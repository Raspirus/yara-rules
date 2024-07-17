
rule SIGNATURE_BASE_Redsails_EXE : FILE
{
	meta:
		description = "Detects Red Sails Hacktool by WinDivert references"
		author = "Florian Roth (Nextron Systems)"
		id = "e7ebbebf-e2d6-5cd3-b859-b804d39d1641"
		date = "2017-10-02"
		modified = "2023-12-05"
		reference = "https://github.com/BeetleChunks/redsails"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_redsails.yar#L11-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fe9232989fb29686f11ee8cd59090fb6602301b00ff12d4a0dff8279a1718086"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"

	strings:
		$s1 = "bWinDivert64.dll" fullword ascii
		$s2 = "bWinDivert32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <6000KB and all of them )
}