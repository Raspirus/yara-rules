
rule ELASTIC_Linux_Trojan_Ngioweb_7926Bc8E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "7926bc8e-110f-4b8a-8cc5-003732b6fcfd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
		logic_hash = "ac42dd714696825d64402861e96122cce7cd09ae8d9c43a19dd9cf95d7b09610"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "246e06d73a3a61ade6ac5634378489890a5585e84be086e0a81eb7586802e98f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { ED 74 31 48 8B 5B 10 4A 8D 6C 3B FC 48 39 EB 77 23 8B 3B 48 83 }

	condition:
		all of them
}