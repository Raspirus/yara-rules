
rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug21_3 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
		author = "Max Altgelt"
		id = "a7bca62b-c8f1-5a38-81df-f3d4582a590b"
		date = "2021-08-23"
		modified = "2023-12-05"
		reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L51-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f071aaa8918b359f786f2ac7447eeaedb5a6fca9e0a0c0e8820e011244424503"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Page Language=" ascii nocase

	condition:
		uint16(0)==0x8230 and filesize <10KB and $s1
}