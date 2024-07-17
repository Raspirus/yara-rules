
rule SIGNATURE_BASE_MAL_ELF_LNX_Mirai_Oct10_2 : FILE
{
	meta:
		description = "Detects ELF malware Mirai related"
		author = "Florian Roth (Nextron Systems)"
		id = "421b7708-030e-50d1-bf2e-e91758a48c00"
		date = "2018-10-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L124-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "47d20bdf64c18c925dc1391b022278f913b7fbce13988a7b5de2e9d135c5a265"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"

	strings:
		$c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }

	condition:
		uint16(0)==0x457f and filesize <200KB and all of them
}