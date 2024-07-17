rule ELASTIC_Linux_Trojan_Xorddos_1A562D3B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "1a562d3b-bc59-4cb7-9ac1-7a4a79232869"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L357-L375"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
		logic_hash = "8d3b369bdcecd675f99cedf26dba202256555be0f5feae612404f9b5e109fa93"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e052e99f15f5a0f704c04cae412cf4b1f01a8ee6e4ce880aedc79cf5aee9631a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }

	condition:
		all of them
}