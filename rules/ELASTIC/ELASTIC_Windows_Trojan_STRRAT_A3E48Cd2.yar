rule ELASTIC_Windows_Trojan_STRRAT_A3E48Cd2 : MEMORY
{
	meta:
		description = "Detects Windows Trojan Strrat (Windows.Trojan.STRRAT)"
		author = "Elastic Security"
		id = "a3e48cd2-e65f-40db-ab55-8015ad871dd6"
		date = "2024-03-13"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_STRRAT.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "97e67ac77d80d26af4897acff2a3f6075e0efe7997a67d8194e799006ed5efc9"
		logic_hash = "32f79695829f703bf9996d212aeb563791aed28e1bbb9f700cb45325fd02db77"
		score = 75
		quality = 75
		tags = "MEMORY"
		fingerprint = "efda9a8bd5f9e227a6696de1b4ea7eb7343b08563cfcbe73fdd75164593bd111"
		severity = 100
		arch_context = "x86"
		scan_context = "memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "strigoi/server/ping.php?lid="
		$str2 = "/strigoi/server/?hwid="

	condition:
		all of them
}