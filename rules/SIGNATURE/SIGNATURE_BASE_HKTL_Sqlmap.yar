rule SIGNATURE_BASE_HKTL_Sqlmap : FILE
{
	meta:
		description = "Detects sqlmap hacktool"
		author = "Florian Roth (Nextron Systems)"
		id = "da2029dd-c4ce-557f-a409-c468fa3deef3"
		date = "2018-10-09"
		modified = "2023-12-05"
		reference = "https://github.com/sqlmapproject/sqlmap"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4512-L4525"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9aa13bc2db40f5ab3debd617c84b1e11805d137bc55e9088bc9a0c23e185dfce"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"

	strings:
		$x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
		$x2 = "if conf.get(\"dumper\"):" fullword ascii

	condition:
		filesize <50KB and 1 of them
}