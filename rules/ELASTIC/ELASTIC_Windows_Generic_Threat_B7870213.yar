
rule ELASTIC_Windows_Generic_Threat_B7870213 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b7870213-e235-4b2d-83c1-e3c7c486ee8d"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3224-L3242"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "04cb0d5eecea673acc575e54439398cc00e78cc54d8f43c4b9bc353e4fc4430d"
		logic_hash = "79b8385543def42259cd9c09d4d7059ff6bb02a9e87cff1bc0a8861e3b333c5f"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "c087f84c8572dba64da62c9f317969cbce46e78656e0a75489788add787c2781"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 75 28 6B 6E 4E 30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 32 32 32 33 32 34 32 35 32 36 32 37 32 38 32 39 33 30 33 31 33 32 33 33 33 34 33 35 33 36 33 37 33 38 33 39 34 30 34 31 34 32 34 33 34 34 34 35 34 36 34 37 34 38 34 39 35 30 35 31 35 32 35 33 35 34 35 35 35 36 35 37 35 38 35 39 36 30 36 31 36 32 36 33 36 34 36 35 36 36 36 37 36 38 36 39 37 30 37 31 37 32 37 33 37 34 37 35 37 36 37 37 37 38 37 39 38 30 38 31 38 32 38 33 38 34 38 35 38 36 38 37 38 38 38 39 39 30 39 31 39 32 39 33 39 34 39 35 39 36 39 37 39 38 39 39 }

	condition:
		all of them
}