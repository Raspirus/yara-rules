rule ELASTIC_Macos_Trojan_Fplayer_1C1Fae37 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Fplayer (MacOS.Trojan.Fplayer)"
		author = "Elastic Security"
		id = "1c1fae37-8d19-4129-a715-b78163f93fd2"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Fplayer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f57e651088dee2236328d09705cef5e98461e97d1eb2150c372d00ca7c685725"
		logic_hash = "0d65717bdbac694ffb2535a1ff584f7ec2aa7b553a08d29113c6e2bd7b2ff1aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "abeb3cd51c0ff2e3173739c423778defb9a77bc49b30ea8442e6ec93a2d2d8d2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 56 41 55 41 54 53 48 83 EC 48 4D 89 C4 48 89 C8 48 89 D1 49 89 F6 49 89 FD 49 }

	condition:
		all of them
}