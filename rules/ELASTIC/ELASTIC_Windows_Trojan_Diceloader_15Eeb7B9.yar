rule ELASTIC_Windows_Trojan_Diceloader_15Eeb7B9 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Diceloader (Windows.Trojan.Diceloader)"
		author = "Elastic Security"
		id = "15eeb7b9-311f-477b-8ae1-b8f689a154b7"
		date = "2021-04-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Diceloader.yar#L27-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a1202df600d11ad2c61050e7ba33701c22c2771b676f54edd1846ef418bea746"
		logic_hash = "f1ab9ad69f9ea75343c7404b82a3f7a4976a442b980a98fe5b95c55d4f9cb34e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4cc70bec5d241c6f84010fbfe2eafbc6ec6d753df2bb3f52d9498b54b11fc8cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { E9 92 9D FF FF C3 E8 }
		$a2 = { E9 E8 61 FF FF C3 E8 }

	condition:
		any of them
}