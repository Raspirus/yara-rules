
rule SIGNATURE_BASE_EXPL_MAL_Maldoc_OBFUSCT_MHTML_Sep21_1 : CVE_2021_40444 FILE
{
	meta:
		description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
		author = "Florian Roth (Nextron Systems)"
		id = "781cfd61-d5ac-58e5-868f-dbd2a2df3500"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2021_40444.yar#L27-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "11a73572970d2d85d308330119a2c5243f2848ae78a861decdb0cdbde0d9d1c2"
		score = 90
		quality = 85
		tags = "CVE-2021-40444, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide

	condition:
		filesize <25KB and all of them
}