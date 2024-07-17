rule ELASTIC_Linux_Trojan_Xorddos_7909Cdd2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "7909cdd2-8a49-4f51-ae16-1ffe321a29d4"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L257-L275"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
		logic_hash = "4b2557ab78d22ae4f46e5813ba5dc4663cd92b945a1add3155f77d3030ccc92d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5c982596276c8587a88bd910bb2e75a7f72ea7a57c401ffa387aced33f9ac2b9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }

	condition:
		all of them
}