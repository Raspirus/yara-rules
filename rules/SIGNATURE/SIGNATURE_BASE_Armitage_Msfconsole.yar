rule SIGNATURE_BASE_Armitage_Msfconsole : FILE
{
	meta:
		description = "Detects Armitage component"
		author = "Florian Roth (Nextron Systems)"
		id = "9c610cd0-663e-54ea-a0f2-6c044fc45d23"
		date = "2017-12-24"
		modified = "2022-08-18"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_armitage.yar#L14-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cf9df9858ca584288288fd0b55fdcf65aeea410f25531ee3d8cf48c30d23824a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"

	strings:
		$s1 = "\\umeterpreter\\u >" ascii
		$s3 = "^meterpreter >" fullword ascii
		$s11 = "\\umsf\\u>" ascii

	condition:
		filesize <1KB and 2 of them
}