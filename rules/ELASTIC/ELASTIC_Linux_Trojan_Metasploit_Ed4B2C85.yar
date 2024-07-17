rule ELASTIC_Linux_Trojan_Metasploit_Ed4B2C85 : FILE MEMORY
{
	meta:
		description = "Detects x64 msfvenom bind TCP random port payloads"
		author = "Elastic Security"
		id = "ed4b2c85-730f-4a77-97ed-5439a0493a4a"
		date = "2024-05-07"
		modified = "2024-05-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Metasploit.yar#L329-L348"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
		logic_hash = "79e466b2f40a6769db498cc28cb22ba72ec20f92c8450d6f1f8301d00012f967"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c38513fa6b1ed23ec91ae316af9793c5c01ac94b43ba5502f9c32a0854aec96f"
		threat_name = "Linux.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }

	condition:
		all of them
}