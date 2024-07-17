rule ELASTIC_Linux_Trojan_Xorddos_1D6E10Fd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "1d6e10fd-7404-4597-a97d-cc92849d84f4"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L177-L195"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
		logic_hash = "01ec1af1ca03173e867113c3bec7911990a0c8c2d9f19b5233715a7f7490f5f1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bf9d971a13983f1d0fdc8277e76cd1929523e239ce961316fe1f44cbdf0638a8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }

	condition:
		all of them
}