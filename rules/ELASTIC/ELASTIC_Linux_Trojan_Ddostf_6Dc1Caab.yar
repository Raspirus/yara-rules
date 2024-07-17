rule ELASTIC_Linux_Trojan_Ddostf_6Dc1Caab : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ddostf (Linux.Trojan.Ddostf)"
		author = "Elastic Security"
		id = "6dc1caab-be84-4f27-a059-2acffc20ca2c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ddostf.yar#L40-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f4587bd45e57d4106ebe502d2eaa1d97fd68613095234038d67490e74c62ba70"
		logic_hash = "fd70960ed6e06f4d152bbd211fbe491dad596010da12cd53c93b577b551b8053"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "43bcb29d92e0ed2dfd0ff182991864f8efabd16a0f87e8c3bb453b47bd8e272b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FC 01 83 45 F8 01 83 7D F8 5A 7E E6 C7 45 F8 61 00 00 00 EB 14 8B }

	condition:
		all of them
}