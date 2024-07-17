
rule ELASTIC_Windows_Trojan_Sysjoker_34559Bcd : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sysjoker (Windows.Trojan.SysJoker)"
		author = "Elastic Security"
		id = "34559bcd-661a-4213-b896-2d7f882a16ef"
		date = "2022-02-21"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SysJoker.yar#L24-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
		logic_hash = "ebe7f6037f14e37b6efe81614c06c6d26fe0cc17d0475b8b19715f80d0d9aad3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b1e01d0b94a60f6f5632a14d3d32f78bbe3049886ea3a3e838a29fb790a45918"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "\\txc1.txt\" && type \"" ascii fullword
		$a2 = "tempo1.txt" nocase
		$a3 = "user_token="
		$a4 = "{\"status\":\"success\",\"result\":\"" ascii fullword
		$a5 = "\",\"av\":\"" ascii fullword
		$a6 = "aSwpEHc0QyIxPRAqNmkeEwskMW8HODkkYRkCICIrJysHNmtlIzQiChMiGAxzQg==" ascii fullword
		$a7 = "ESQuBT8uQyglJy4QOicGXDMiayYtPQ==" ascii fullword

	condition:
		4 of them
}