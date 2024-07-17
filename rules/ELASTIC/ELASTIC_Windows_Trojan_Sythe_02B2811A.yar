
rule ELASTIC_Windows_Trojan_Sythe_02B2811A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sythe (Windows.Trojan.Sythe)"
		author = "Elastic Security"
		id = "02b2811a-2ced-42b6-a9f1-6d983d1dc986"
		date = "2023-05-10"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Sythe.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2d54a8ba40cc9a1c74db7a889bc75a38f16ae2d025268aa07851c1948daa1b4d"
		logic_hash = "ba472b35f583dd4cf125df575129d07de289d6d7dc12ecdcc518ce1eb9f18def"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4dd9764e285985fbea5361e5edfa04e75fb8e3e7945cbbf712ea0183471e67ae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "loadmodule"
		$a2 = "--privileges"
		$a3 = "--shutdown"
		$a4 = "SetClientThreadID"

	condition:
		all of them
}