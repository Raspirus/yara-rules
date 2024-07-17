rule ELASTIC_Linux_Trojan_Zerobot_3A5B56Dd : FILE MEMORY
{
	meta:
		description = "Strings found in the Zerobot Spoofed Header method"
		author = "Elastic Security"
		id = "3a5b56dd-e829-44bb-ae70-d7001addd057"
		date = "2022-12-16"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Zerobot.yar#L28-L51"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
		logic_hash = "2491fff4ad0327e0440d842f221fb6623c8efd97e2991bf2090abceaef9c2ccf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9800a241ab602434426830110ce244cdfd0023176e5fa64e2b8761234ed6f529"
		threat_name = "Linux.Trojan.Zerobot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$HootSpoofHeader_0 = "X-Forwarded-Proto: Http"
		$HootSpoofHeader_1 = "X-Forwarded-Host: %s, 1.1.1.1"
		$HootSpoofHeader_2 = "Client-IP: %s"
		$HootSpoofHeader_3 = "Real-IP: %s"
		$HootSpoofHeader_4 = "X-Forwarded-For: %s"

	condition:
		3 of them
}