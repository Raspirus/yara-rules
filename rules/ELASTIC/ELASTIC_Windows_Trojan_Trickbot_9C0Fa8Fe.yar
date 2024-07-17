
rule ELASTIC_Windows_Trojan_Trickbot_9C0Fa8Fe : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "9c0fa8fe-8d5f-4581-87a0-92a4ed1b32b3"
		date = "2021-07-13"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L956-L974"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
		logic_hash = "23aebc3139c34ecd609db7920fa0d5e194173409e1862555e4c468dad6c46299"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bd49ed2ee65ff0cfa95efc9887ed24de3882c5b5740d0efc6b9690454ca3f5dc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }

	condition:
		all of them
}