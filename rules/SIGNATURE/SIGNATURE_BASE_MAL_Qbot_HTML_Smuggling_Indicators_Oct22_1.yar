
rule SIGNATURE_BASE_MAL_Qbot_HTML_Smuggling_Indicators_Oct22_1 : FILE
{
	meta:
		description = "Detects double encoded PKZIP headers as seen in HTML files used by QBot"
		author = "Florian Roth (Nextron Systems)"
		id = "8034d6af-4dae-5ff6-b635-efb5175fe4d1"
		date = "2022-10-07"
		modified = "2023-12-05"
		reference = "https://twitter.com/ankit_anubhav/status/1578257383133876225?s=20&t=Bu3CCJCzImpTGOQX_KGsdA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_qbot_payloads.yar#L2-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a5bd9eb72205f1398ec0b8773751309699b3267e0272dacf2728f8495c0c0ec2"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "4f384bcba31fda53e504d0a6c85cee0ce3ea9586226633d063f34c53ddeaca3f"
		hash2 = "8e61c2b751682becb4c0337f5a79b2da0f5f19c128b162ec8058104b894cae9b"
		hash3 = "c5d23d991ce3fbcf73b177bc6136d26a501ded318ccf409ca16f7c664727755a"
		hash4 = "5072d91ee0d162c28452123a4d9986f3df6b3244e48bf87444ce88add29dd8ed"
		hash5 = "ff4e21f788c36aabe6ba870cf3b10e258c2ba6f28a2d359a25d5a684c92a0cad"

	strings:
		$sd1 = "VUVzREJCUUFBUUFJQ"
		$sd2 = "VFc0RCQlFBQVFBSU"
		$sd3 = "VRXNEQkJRQUFRQUlB"
		$sdr1 = "QJFUUBFUUCJERzVUV"
		$sdr2 = "USBFVQBFlQCR0cFV"
		$sdr3 = "BlUQRFUQRJkQENXRV"
		$st1 = "VlVWelJFSkNVVUZCVVVGSl"
		$st2 = "ZVVnpSRUpDVVVGQlVVRkpR"
		$st3 = "WVVZ6UkVKQ1VVRkJVVUZKU"
		$st4 = "VkZjMFJDUWxGQlFWRkJTV"
		$st5 = "ZGYzBSQ1FsRkJRVkZCU1"
		$st6 = "WRmMwUkNRbEZCUVZGQlNV"
		$st7 = "VlJYTkVRa0pSUVVGUlFVbE"
		$st8 = "ZSWE5FUWtKUlFVRlJRVWxC"
		$st9 = "WUlhORVFrSlJRVUZSUVVsQ"
		$str1 = "UUpGVVVCRlVVQ0pFUnpWVV"
		$str2 = "FKRlVVQkZVVUNKRVJ6VlVW"
		$str3 = "RSkZVVUJGVVVDSkVSelZVV"
		$str4 = "VVNCRlZRQkZsUUNSMGNGV"
		$str5 = "VTQkZWUUJGbFFDUjBjRl"
		$str6 = "VU0JGVlFCRmxRQ1IwY0ZW"
		$str7 = "QmxVUVJGVVFSSmtRRU5YUl"
		$str8 = "JsVVFSRlVRUkprUUVOWFJW"
		$str9 = "CbFVRUkZVUVJKa1FFTlhSV"
		$htm = "<html" ascii
		$eml = "Content-Transfer-Encoding:" ascii

	condition:
		filesize <10MB and ((1 of ($sd*) and $htm and not $eml) or (1 of ($st*) and $eml))
}