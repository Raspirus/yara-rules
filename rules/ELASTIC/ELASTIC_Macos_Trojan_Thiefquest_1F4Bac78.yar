
rule ELASTIC_Macos_Trojan_Thiefquest_1F4Bac78 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "1f4bac78-ef2b-49cd-8852-e84d792f6e57"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L104-L122"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		logic_hash = "96db33e135138846f978026867bb2536226539997d060f41e7081f7f29b66c85"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e7d1e2009ff9b33d2d237068e2af41a8aa9bd44a446a2840c34955594f060120"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }

	condition:
		all of them
}