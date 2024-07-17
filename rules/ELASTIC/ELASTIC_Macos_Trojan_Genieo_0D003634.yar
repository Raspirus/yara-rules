
rule ELASTIC_Macos_Trojan_Genieo_0D003634 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
		author = "Elastic Security"
		id = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Genieo.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
		logic_hash = "0412f88408fb14d1126ef091d0a5cc0ee2b2e39aeb241bef55208b59830ca993"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }

	condition:
		all of them
}