rule ELASTIC_Linux_Trojan_Gafgyt_D996D335 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d996d335-e049-4052-bf36-6cd07c911a8b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L654-L672"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b511eacd4b44744c8cf82d1b4a9bc6f1022fe6be7c5d17356b171f727ddc6eda"
		logic_hash = "212c75ab61eac8b3ed2049966628dfc81ae5a620b4a4b38aaa0696d594910dea"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e9ccb8412f32187c309b0e9afcc3a6da21ad2f1ffa251c27f9f720ccb284e3ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 }

	condition:
		all of them
}