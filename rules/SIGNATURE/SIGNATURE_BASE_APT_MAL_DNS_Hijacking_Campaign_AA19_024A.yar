
rule SIGNATURE_BASE_APT_MAL_DNS_Hijacking_Campaign_AA19_024A : FILE
{
	meta:
		description = "Detects malware used in DNS Hijackign campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "6a476052-ba4e-5049-9c7a-f8949d26e7b5"
		date = "2019-01-25"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/AA19-024A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_aa19_024a.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8e9ec132df6cf6a89f6694682292feec0f3a762c2df6b1dc8180d9ab68e7183b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
		hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"

	strings:
		$s2 = "/Client/Login?id=" fullword ascii
		$s3 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
		$s4 = ".\\Configure.txt" fullword ascii
		$s5 = "Content-Disposition: form-data; name=\"files\"; filename=\"" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"txts\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}