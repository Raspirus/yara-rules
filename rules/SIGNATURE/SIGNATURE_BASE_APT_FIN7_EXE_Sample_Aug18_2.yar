rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_2 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "4522cd85-ba85-5afd-8600-1ebabfaf6d02"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L110-L124"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8e62c9488f211635ae30633a0d894b00e0ba2a7e7d4cb628117a166d4f0f9697"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"

	strings:
		$s1 = "constructor or from DllMain." fullword ascii
		$s2 = "Network Software Ltd0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}