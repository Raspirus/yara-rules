rule ELASTIC_Windows_Backdoor_Goldbackdoor_91902940 : FILE MEMORY
{
	meta:
		description = "Detects Windows Backdoor Goldbackdoor (Windows.Backdoor.Goldbackdoor)"
		author = "Elastic Security"
		id = "91902940-a291-4fc6-81c5-2cde2328e8d9"
		date = "2022-04-29"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Backdoor_Goldbackdoor.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
		logic_hash = "71e26cce6d730560e1303b2a4f49d0da6d1341263bb47ade46338f03e528cbf7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "83a404a24e54bd05319d3df3a830f1ffe51d30f71ca55d63ca152d5169511df4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$pdf = "D:\\Development\\GOLD-BACKDOOR\\"
		$agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.3112.113 Safari/537.36"
		$str0 = "client_id"
		$str1 = "client_secret"
		$str2 = "redirect_uri"
		$str3 = "refresh_token"
		$a = { 56 57 8B 7D 08 8B F1 6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 46 30 85 C0 75 ?? 33 C0 5F 5E }
		$b = { 66 8B 02 83 C2 02 66 85 C0 75 ?? 2B D1 D1 FA 75 ?? 33 C0 E9 ?? ?? ?? ?? 6A 40 8D 45 ?? 6A 00 50 E8 }

	condition:
		($pdf and $agent) or ( all of ($str*) and $a and $b)
}