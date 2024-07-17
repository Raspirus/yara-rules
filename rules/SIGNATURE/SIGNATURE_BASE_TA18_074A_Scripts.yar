rule SIGNATURE_BASE_TA18_074A_Scripts : FILE
{
	meta:
		description = "Detects malware mentioned in TA18-074A"
		author = "Florian Roth (Nextron Systems)"
		id = "4c786098-c5f4-529b-8732-03183dfa94b5"
		date = "2018-03-16"
		modified = "2022-08-18"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_074A.yar#L53-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "888ddd59b388033604474fc008f830159a9a104683fb052e7497b83118cbb8aa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"

	strings:
		$s1 = "Running -s cmd /c query user on " ascii

	condition:
		filesize <600KB and 1 of them
}