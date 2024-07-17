
rule ELASTIC_Macos_Trojan_Genieo_9E178C0B : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
		author = "Elastic Security"
		id = "9e178c0b-02ca-499b-93d1-2b6951d41435"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Genieo.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
		logic_hash = "212f96ca964aceeb80c6d3282d488cfbb74aeffb9c0c9dd840a3a28f9bbdcbea"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }

	condition:
		all of them
}