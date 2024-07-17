rule ELASTIC_Linux_Trojan_Xorddos_410256Ac : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "410256ac-fc7d-47f1-b7b8-82f1ee9f2bfb"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L377-L395"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
		logic_hash = "88227af6d2f365b761961bdf4b94bed81bca79e23d546e69900faa17c3e4dc71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "aa7f1d915e55c3ef178565ed12668ddd71bf3e982dba1f2436c98cceef2c376d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }

	condition:
		all of them
}