
rule ELASTIC_Windows_Trojan_Pizzapotion_D334C613 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Pizzapotion (Windows.Trojan.PizzaPotion)"
		author = "Elastic Security"
		id = "d334c613-2ef2-4627-b482-cc87589d253a"
		date = "2023-09-13"
		modified = "2023-09-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PizzaPotion.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "37bee101cf34a84cba49adb67a555c6ebd3b8ac7c25d50247b0a014c82630003"
		logic_hash = "de7d395c8a993abf9858858e56ba0ec4acbf0fa1c8bfe4a34ae95be2205967fc"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4c1ed20b669750f2bc837b184226608e2e8473ac60881fbdd47709e147616889"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%s%sd.sys" ascii fullword
		$a2 = "curl -v -k -F \"file=@" ascii fullword
		$a3 = "; type=image/jpeg\" --referer drive.google.com --cookie"
		$a4 = "%sd.sys -r -inul"
		$a5 = ".xls d:\\*.xlsx d:\\*.ppt d:\\*.pptx d:\\*.pfx" ascii fullword
		$a6 = "-x\"*.exe\" -x\"*.dll\" -x\"*.jpg\" -x\"*.jpeg\""

	condition:
		4 of them
}