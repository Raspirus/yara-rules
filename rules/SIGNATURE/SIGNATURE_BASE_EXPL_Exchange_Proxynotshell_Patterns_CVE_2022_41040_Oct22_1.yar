
rule SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1 : SCRIPT
{
	meta:
		description = "Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information)"
		author = "Florian Roth (Nextron Systems)"
		id = "d2812fcd-0a20-5bbd-a9e1-9cca1ed58aa3"
		date = "2022-10-11"
		modified = "2023-03-15"
		old_rule_name = "EXPL_Exchange_ProxyNoShell_Patterns_CVE_2022_41040_Oct22_1"
		reference = "https://github.com/kljunowsky/CVE-2022-41040-POC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_cve_2022_41040_proxynoshell.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "81b0f0fea2762beb47826ff95545c87e960e098b9d5f45eacfe07b3ecf319ac5"
		score = 75
		quality = 85
		tags = "SCRIPT"

	strings:
		$sr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}owershell/ nocase ascii
		$sa1 = " 200 "
		$fp1 = " 444 "
		$fp2 = " 404 "
		$fp2b = " 401 "
		$fp3 = "GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId=" ascii
		$fp4 = "@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com" ascii

	condition:
		$sr1 and 1 of ($sa*) and not 1 of ($fp*)
}