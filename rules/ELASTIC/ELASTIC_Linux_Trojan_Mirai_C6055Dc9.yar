
rule ELASTIC_Linux_Trojan_Mirai_C6055Dc9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "c6055dc9-316b-478d-9997-1dbf455cafcc"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1641-L1659"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c1718d7fdeef886caa33951e75cbd9139467fa1724605fdf76c8cdb1ec20e024"
		logic_hash = "4d9d7c44f0d3ae60275720ae5faf3c25c368aa6e7d9ab5ed706a30f9a7ffd3b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b95f582edf2504089ddd29ef1a0daf30644b364f3d90ede413a2aa777c205070"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 7F 43 80 77 39 CF 7E 09 83 C8 FF 5A 5D 8A 0E }

	condition:
		all of them
}