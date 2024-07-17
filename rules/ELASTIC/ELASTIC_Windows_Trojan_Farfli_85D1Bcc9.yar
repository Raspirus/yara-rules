
rule ELASTIC_Windows_Trojan_Farfli_85D1Bcc9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Farfli (Windows.Trojan.Farfli)"
		author = "Elastic Security"
		id = "85d1bcc9-c3c7-454c-a77f-0e0de933c4c3"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Farfli.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e3e9ea1b547cc235e6f1a78b4ca620c69a54209f84c7de9af17eb5b02e9b58c3"
		logic_hash = "746eb5a2583077189d82d1a96b499ff383f31220845bd8a6df5b7a7ceb11e6fb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "56a5e4955556d08b80849ea5775f35f5a32999d6b5df92357ab142a4faa74ac3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { AB 66 AB C6 45 D4 25 C6 45 D5 73 C6 45 D6 5C C6 45 D7 25 C6 45 }

	condition:
		all of them
}