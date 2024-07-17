
rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug21_2 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
		author = "Florian Roth (Nextron Systems)"
		id = "a351a466-695e-570e-8c7f-9c6c0534839c"
		date = "2021-08-13"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L36-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4ede197d482f0a9e553ba857b5049e7b7405e3df92460e19418fa0653c844982"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Page Language=" ascii nocase

	condition:
		uint32(0)==0x4e444221 and filesize <2MB and $s1
}