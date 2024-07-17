rule ELASTIC_Multi_Ransomware_Blackcat_C4B043E6 : FILE MEMORY
{
	meta:
		description = "Detects Multi Ransomware Blackcat (Multi.Ransomware.BlackCat)"
		author = "Elastic Security"
		id = "c4b043e6-ff5f-4492-94e3-fd688d690738"
		date = "2022-09-12"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Ransomware_BlackCat.yar#L45-L63"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
		logic_hash = "1262ca76581920f08a6482ead68023fdfff08a9ddd19e00230054e3167dc184c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3e89858e90632ad5f4831427bd630252113b735c51f7a1aa1eab8ba6e4c16f18"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }

	condition:
		all of them
}