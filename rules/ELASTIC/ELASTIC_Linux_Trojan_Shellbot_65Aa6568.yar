rule ELASTIC_Linux_Trojan_Shellbot_65Aa6568 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Shellbot (Linux.Trojan.Shellbot)"
		author = "Elastic Security"
		id = "65aa6568-491a-4a51-b921-c6c228cfca11"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Shellbot.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "457d1f4e1db41a9bdbfad78a6815f42e45da16ad0252673b9a2b5dcefc02c47b"
		logic_hash = "46558801151ddc2f25bf46a278719f027acca2a18d2a9fcb275f4d787fbb1f0b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2cd606ecaf17322788a5ee3b6bd663bed376cef131e768bbf623c402664e9270"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 72 00 73 74 72 63 6D 70 00 70 61 6D 5F 70 72 6F 6D 70 74 00 }

	condition:
		all of them
}