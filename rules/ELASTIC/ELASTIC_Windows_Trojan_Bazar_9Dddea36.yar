rule ELASTIC_Windows_Trojan_Bazar_9Dddea36 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bazar (Windows.Trojan.Bazar)"
		author = "Elastic Security"
		id = "9dddea36-1345-434b-8ce6-54d2eab39616"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bazar.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "63df43daa61f9a0fbea2e5409b8f0063f7af3363b6bc8d6984ce7e90c264727d"
		logic_hash = "cf88e2e896fce742ad3325d53523167d6eb42188309ed4e66f73601bbb85574e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e322e36006cc017d5d5d9887c89b180c5070dbe5a9efd9fb7ae15cda5b726d6c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { C4 10 5B 5F 5E C3 41 56 56 57 55 53 48 83 EC 18 48 89 C8 48 }

	condition:
		all of them
}