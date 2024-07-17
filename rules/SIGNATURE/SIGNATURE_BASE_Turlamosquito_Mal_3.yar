import "pe"


rule SIGNATURE_BASE_Turlamosquito_Mal_3 : FILE
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		author = "Florian Roth (Nextron Systems)"
		id = "c83e0a93-3f8d-572d-ac1a-92fef0b3d3f6"
		date = "2018-02-22"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_mosquito.yar#L54-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0f59c130b500625466da0c8b5bfd84051ee59a3b6261ee3d990d4c355b10672b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "443cd03b37fca8a5df1bbaa6320649b441ca50d1c1fcc4f5a7b94b95040c73d1"

	strings:
		$x1 = "InstructionerDLL.dll" fullword ascii
		$s1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
		$s2 = "/scripts/m/query.php?id=" fullword wide
		$s3 = "SELECT * FROM AntiVirusProduct" fullword ascii
		$s4 = "Microsoft Update" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="88488fe0b8bcd6e379dea6433bb5d7d8" or (pe.exports("InstallRoutineW") and pe.exports("StartRoutine")) or $x1 or 3 of them )
}