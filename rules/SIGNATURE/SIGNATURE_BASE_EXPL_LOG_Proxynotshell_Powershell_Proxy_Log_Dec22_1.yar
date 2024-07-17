
rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_Powershell_Proxy_Log_Dec22_1 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "5af3ae70-8897-593f-a413-82ca1d1ba961"
		date = "2022-12-22"
		modified = "2023-01-26"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_proxynotshell_owassrf_dec22.yar#L68-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f2aac61bc17f74901ec8d638d5cfaaa45bbd2a4e40e5d915bf2a946daed411d2"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$re1 = /,\/[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll][^\n]{0,50},Kerberos,true,[^\n]{0,50},200,0,,,,[^\n]{0,2000};OnEndRequest\.End\.ContentType=application\/soap\+xml charset UTF-8;S:ServiceCommonMetadata\.HttpMethod=POST;/ ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		$re1 and not 1 of ($fp*)
}