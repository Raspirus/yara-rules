rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_1 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "a61f6582-474f-5b6f-b8f5-329c0bcc4017"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxynotshell_owassrf_dec22.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e8f5a3440f8b4b1850fddbd19f63796ad0f28178c678e9f464b7e4ab5ca944f"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$s1 = "/owa/mastermailbox%40outlook.com/powershell" ascii wide
		$sa1 = " 200 " ascii wide
		$sa2 = " POST " ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		all of ($s*) and not 1 of ($fp*)
}