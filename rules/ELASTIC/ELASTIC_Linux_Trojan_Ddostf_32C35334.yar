rule ELASTIC_Linux_Trojan_Ddostf_32C35334 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ddostf (Linux.Trojan.Ddostf)"
		author = "Elastic Security"
		id = "32c35334-f264-4509-b5c4-b07e477bd07d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ddostf.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d62d450d48756c09f8788b27301de889c864e597924a0526a325fa602f91f376"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f71d1e9188f67147de8808d65374b4e34915e9d60ff475f7fc519c8918c75724"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0E 18 41 0E 1C 41 0E 20 48 0E 10 00 4C 00 00 00 64 4B 00 00 }

	condition:
		all of them
}