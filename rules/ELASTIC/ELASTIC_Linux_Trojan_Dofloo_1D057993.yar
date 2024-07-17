
rule ELASTIC_Linux_Trojan_Dofloo_1D057993 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dofloo (Linux.Trojan.Dofloo)"
		author = "Elastic Security"
		id = "1d057993-0a46-4014-8ab6-aa9e9d93dfa1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dofloo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		logic_hash = "c5e15e21946816052d5a8dc293db3830f1d6d06cdbf22eb8667b655206dbbc1f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c4bb948b85777b1f5df89fafba0674bc245bbda1962c576abaf0752f49c747d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 88 45 DB 83 EC 04 8B 45 F8 83 C0 03 89 45 D4 8B 45 D4 89 }

	condition:
		all of them
}