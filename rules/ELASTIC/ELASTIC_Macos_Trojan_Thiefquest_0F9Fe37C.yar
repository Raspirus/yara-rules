rule ELASTIC_Macos_Trojan_Thiefquest_0F9Fe37C : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "0f9fe37c-77df-4d3d-be8a-c62ea0f6863c"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L84-L102"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		logic_hash = "84f9e8938d7e2b0210003fc8334b8fa781a40afffeda8d2341970b84ed5d3b5a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2e809d95981f0ff813947f3be22ab3d3c000a0d348131d5d6c8522447818196d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }

	condition:
		all of them
}