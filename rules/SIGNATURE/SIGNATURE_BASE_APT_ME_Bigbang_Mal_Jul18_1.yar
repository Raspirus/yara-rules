rule SIGNATURE_BASE_APT_ME_Bigbang_Mal_Jul18_1 : FILE
{
	meta:
		description = "Detects malware from Big Bang report"
		author = "Florian Roth (Nextron Systems)"
		id = "f30b2e11-f90a-5068-8eaa-25f11218ec6c"
		date = "2018-07-09"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bigbang.yar#L31-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "da45482b465549fce0f088c5818dff4a734faa2e4fbcec43b750893d1c3fefad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
		hash2 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"

	strings:
		$s1 = "%Y%m%d-%I-%M-%S" fullword ascii
		$s2 = "/api/serv/requests/%s/runfile/delete" fullword ascii
		$s3 = "\\part.txt" ascii
		$s4 = "\\ALL.txt" ascii
		$s5 = "\\sat.txt" ascii
		$s6 = "runfile.proccess_name" fullword ascii
		$s7 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 4 of them
}