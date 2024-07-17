import "pe"


rule SIGNATURE_BASE_Tophat_BAT : FILE
{
	meta:
		description = "Auto-generated rule - file cgen.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "81e84f1b-0ee7-530d-91ea-645c0994e68f"
		date = "2018-01-29"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_tophat.yar#L62-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5dc58fa39d8b2aed95b39da575191fe5d10d5dd95b57c320cde8983505e7184f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f998271c4140caad13f0674a192093092e2a9f7794a7fbbdaa73ae8f2496c387"
		hash2 = "0fbc6fd653b971c8677aa17ecd2749200a4a563f9dd5409cfb26d320618db3e2"

	strings:
		$s1 = "= New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"" ascii
		$s2 = "goto Start" fullword ascii
		$s3 = ":Start" fullword ascii

	condition:
		filesize <5KB and all of them
}