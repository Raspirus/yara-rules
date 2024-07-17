rule ELASTIC_Macos_Trojan_Adload_9B9F86C7 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
		author = "Elastic Security"
		id = "9b9f86c7-e74c-4fc2-bb64-f87473a4b820"
		date = "2021-10-04"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Adload.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
		logic_hash = "82297db23e036f22c90eee7b2654e84df847eb1c2b1ea4dcf358c48a14819709"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "7e70d5574907261e73d746a4ad0b7bce319a9bb3b39a7f1df326284960a7fa38"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }

	condition:
		all of them
}