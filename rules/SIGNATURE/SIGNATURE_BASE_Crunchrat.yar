
rule SIGNATURE_BASE_Crunchrat : FILE
{
	meta:
		description = "Detects CrunchRAT - file CrunchRAT.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "da7d9b5c-6ccc-5960-9daa-4df612545751"
		date = "2017-11-03"
		modified = "2023-12-05"
		reference = "https://github.com/t3ntman/CrunchRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_crunchrat.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e29cfe6dd2ca69b1a8cd0cb36f7513dd9befd392906225196991dc62fcc80870"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "58a07e96497745b6fd5075d569f17b0254c3e50b0234744e0487f7c5dddf7161"

	strings:
		$x1 = "----CrunchRAT" fullword wide
		$x2 = "\\Debug\\CrunchRAT" ascii
		$x3 = "\\Release\\CrunchRAT" ascii
		$s1 = "runCommand" fullword ascii
		$s2 = "<action>download<action>" fullword wide
		$s3 = "Content-Disposition: form-data; name=action" fullword wide
		$s4 = "<action>upload<action>" fullword wide
		$s5 = "/update.php" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <40KB and (1 of ($x*) and 3 of them )
}