
rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Sep21_1 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
		author = "Tobias Michalski"
		id = "d0d23e17-6b6a-51d1-afd9-59cc2404bcd8"
		date = "2021-09-17"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxyshell.yar#L67-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
		logic_hash = "233ec15dff8da5f2beaa931eb06849aa37e548947c1068d688a1695d977605d8"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s = ".FromBase64String(Request["

	condition:
		uint32(0)==0x4e444221 and any of them
}