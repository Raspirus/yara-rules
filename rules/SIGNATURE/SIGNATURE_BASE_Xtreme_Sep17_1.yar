import "pe"


rule SIGNATURE_BASE_Xtreme_Sep17_1 : FILE
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "7517e237-9cad-5619-9028-4c7ab5463040"
		date = "2017-09-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xtreme_rat.yar#L14-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fa78b43f729032291c27f67dc53bd39a85c9a50323c7adf909ca2a8c5acdd861"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "93c89044e8850721d39e935acd3fb693de154b7580d62ed460256cabb75599a6"

	strings:
		$x1 = "ServerKeyloggerU" fullword ascii
		$x2 = "TServerKeylogger" fullword ascii
		$x3 = "XtremeKeylogger" fullword wide
		$x4 = "XTREMEBINDER" fullword wide
		$s1 = "shellexecute=" fullword wide
		$s2 = "[Execute]" fullword wide
		$s3 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" wide

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and (pe.imphash()=="735af2a144f62c50ba8e89c1c59764eb" or (1 of ($x*) or 3 of them ))
}