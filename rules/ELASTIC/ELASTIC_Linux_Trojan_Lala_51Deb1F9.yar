rule ELASTIC_Linux_Trojan_Lala_51Deb1F9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Lala (Linux.Trojan.Lala)"
		author = "Elastic Security"
		id = "51deb1f9-2d5f-4c41-99f3-138c15c35804"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Lala.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f3af65d3307fbdc2e8ce6e1358d1413ebff5eeb5dbedc051394377a4dabffa82"
		logic_hash = "73a7ec230be9aabcc301095c9c075f839852155419bdd8d5542287f34699ab33"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "220bcaa4f18b9474ddd3da921e1189d17330f0eb98fa55a193127413492fb604"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D9 7C F3 89 D8 83 7D FC 00 7D 02 F7 D8 8B 55 08 }

	condition:
		all of them
}