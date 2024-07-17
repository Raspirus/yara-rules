
rule SIGNATURE_BASE_MAL_CMD_Script_Obfuscated_Feb19_1 : FILE
{
	meta:
		description = "Detects obfuscated batch script using env variable sub-strings"
		author = "Florian Roth (Nextron Systems)"
		id = "8cc99ff5-968c-5b12-9aac-72279c1b8a6b"
		date = "2019-03-01"
		modified = "2023-12-05"
		reference = "https://twitter.com/DbgShell/status/1101076457189793793"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_cmd_script_obfuscated.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "71c8831686796c921674ec293b5bdf2c42ae9069b258c85c9e0ca6a7f972daf8"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "deed88c554c8f9bef4078e9f0c85323c645a52052671b94de039b438a8cff382"

	strings:
		$h1 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 }
		$s1 = { 2C 31 25 0D 0A 65 63 68 6F 20 25 25 }

	condition:
		uint16(0)==0x6540 and filesize <200KB and $h1 at 0 and uint16( filesize -3)==0x0d25 and uint8( filesize -1)==0x0a and $s1 in ( filesize -200.. filesize )
}