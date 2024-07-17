
rule ELASTIC_Windows_Trojan_Generic_2993E5A5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Generic (Windows.Trojan.Generic)"
		author = "Elastic Security"
		id = "2993e5a5-26b2-4cfd-8130-4779abcfecb2"
		date = "2024-03-18"
		modified = "2024-03-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Generic.yar#L292-L310"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9f9b926cef69e879462d9fa914dda8c60a01f3d409b55afb68c3fb94bf1a339b"
		logic_hash = "37a10597d1afeb9411f6c652537186628291cbe6af680abe12bb96591add7e78"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "709015984e3c9abaf141b76bf574921466493475182ca30a56dbc3671030b632"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }

	condition:
		1 of them
}