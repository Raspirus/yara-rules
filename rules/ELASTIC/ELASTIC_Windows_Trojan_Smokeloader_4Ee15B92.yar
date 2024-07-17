
rule ELASTIC_Windows_Trojan_Smokeloader_4Ee15B92 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Smokeloader (Windows.Trojan.Smokeloader)"
		author = "Elastic Security"
		id = "4ee15b92-c62f-42d2-bbba-1dac2fa5644f"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Smokeloader.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "09b9283286463b35ea2d5abfa869110eb124eb8c1788eb2630480d058e82abf2"
		logic_hash = "7d5ba6a4cc1f1b87f7ea1963b41749f5488197ea28b31f20a235091236250463"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5d2ed385c76dbb4c1c755ae88b68306086a199a25a29317ae132bc874b253580"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 24 34 30 33 33 8B 45 F4 5F 5E 5B C9 C2 10 00 55 89 E5 83 EC }

	condition:
		all of them
}