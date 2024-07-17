
rule SIGNATURE_BASE_LOG_Proxynotshell_POC_CVE_2022_41040_Nov22 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects logs generated after a successful exploitation using the PoC code against CVE-2022-41040 and CVE-2022-41082 (aka ProxyNotShell) in Microsoft Exchange servers"
		author = "Florian Roth (Nextron Systems)"
		id = "1e47d124-3103-5bf5-946f-b1bb69ff2c8e"
		date = "2022-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/testanull/ProxyNotShell-PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vuln_proxynotshell_cve_2022_41040.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7f91502fd9c59180970fc4253134582b44ba318db03ef4eb575257b2f3818d94"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$aa1 = " POST " ascii wide
		$aa2 = " GET " ascii wide
		$ab1 = " 200 " ascii wide
		$s01 = "/autodiscover.json x=a" ascii wide
		$s02 = "/autodiscover/admin@localhost/" ascii wide

	condition:
		1 of ($aa*) and $ab1 and 1 of ($s*)
}