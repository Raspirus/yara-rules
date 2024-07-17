rule SIGNATURE_BASE_APT_SH_Codecov_Hack_Apr21_1 : FILE
{
	meta:
		description = "Detects manipulated Codecov bash uploader tool that has been manipulated by an unknown actor during March / April 2021"
		author = "Florian Roth (Nextron Systems)"
		id = "b5fb74c4-073e-53af-a207-1672e63c9a64"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://about.codecov.io/security-update/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_codecov_hack.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1aa7723982a1b675ba6694f1af0eb28e5926b974874580bd727cf33a3f8d893a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "Global report uploading tool for Codecov"
		$s1 = "curl -sm 0.5 -d"

	condition:
		uint16(0)==0x2123 and filesize <70KB and all of them
}