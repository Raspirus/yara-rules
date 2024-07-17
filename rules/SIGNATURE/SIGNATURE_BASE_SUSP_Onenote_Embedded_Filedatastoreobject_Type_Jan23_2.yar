
rule SIGNATURE_BASE_SUSP_Onenote_Embedded_Filedatastoreobject_Type_Jan23_2 : FILE
{
	meta:
		description = "Detects suspicious embedded file types in OneNote files"
		author = "Florian Roth (Nextron Systems)"
		id = "0664d202-ab4c-57b6-91ee-ea21ac08909e"
		date = "2023-01-27"
		modified = "2023-12-05"
		reference = "https://blog.didierstevens.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_onenote_phish.yar#L108-L125"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bc07598570b6d4ebc5d14cedfed146c1ad309b8890bc0b9ee5f9ad645c1352e2"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
		$s1 = "<HTA:APPLICATION "

	condition:
		filesize <5MB and $a1 and 1 of ($s*)
}