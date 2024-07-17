rule ELASTIC_Macos_Trojan_Bundlore_650B8Ff4 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "650b8ff4-6cc8-4bfc-ba01-ac9c86410ecc"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "78fd2c4afd7e810d93d91811888172c4788a0a2af0b88008573ce8b6b819ae5a"
		logic_hash = "e8a706db010e9c3d9714d5e7a376e9b2189af382a7b01db9a9e7ee947e9637bb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4f4691f6830684a71e7b3ab322bf6ec4638bf0035adf3177dbd0f02e54b3fd80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 8B 11 00 00 60 80 35 85 11 00 00 12 80 35 7F 11 00 00 8C 80 35 79 11 00 00 }

	condition:
		all of them
}