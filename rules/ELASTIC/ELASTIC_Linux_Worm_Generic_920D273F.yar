rule ELASTIC_Linux_Worm_Generic_920D273F : FILE MEMORY
{
	meta:
		description = "Detects Linux Worm Generic (Linux.Worm.Generic)"
		author = "Elastic Security"
		id = "920d273f-5b2b-4eec-a2b3-8d411f2ea181"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Worm_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "04a65bc73fab91f654d448b2d7f8f15ac782965dcdeec586e20b5c7a8cc42d73"
		logic_hash = "d0ed260857ae3002483ea7ef242b82514caaa95c2700b39dd0a03d39fdde090d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3d4dd13b715249710bc2a02b1628fb68bcccebab876ff6674cad713e93ac53d2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E9 E5 49 86 49 A4 1A 70 C7 A4 AD 2E E9 D9 09 F5 AD CB ED FC 3B }

	condition:
		all of them
}