rule SIGNATURE_BASE_Apt_Projectsauron_Encryption : FILE
{
	meta:
		description = "Rule to detect ProjectSauron string encryption"
		author = "Kaspersky Lab"
		id = "b3139045-54f5-5d59-980b-8510faa9ad0e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_project_sauron.yara#L105-L123"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ae3a681b0cf9ed93d25fa35982daab48c460ba9737eb643ba28a972ea3a7b401"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = {81??02AA02C175??8B??0685}
		$a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
		$a3 = {803E225775??807E019F75??807E02BE75??807E0309}

	condition:
		filesize <5000000 and any of ($a*)
}