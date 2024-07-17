rule SIGNATURE_BASE_SUSP_Officedoc_VBA_Base64Decode : FILE
{
	meta:
		description = "Detects suspicious VBA code with Base64 decode functions"
		author = "Florian Roth (Nextron Systems)"
		id = "99690116-fc89-53d7-8f29-575d75d53fc9"
		date = "2019-06-21"
		modified = "2023-12-05"
		reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_office_dropper.yar#L65-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1fb094c9991f93e9d1003832dc11a58efa8281e9fe844e61e27dfd077f55ad39"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"

	strings:
		$s1 = "B64_CHAR_DICT" ascii
		$s2 = "Base64Decode" ascii
		$s3 = "Base64Encode" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <60KB and 2 of them
}