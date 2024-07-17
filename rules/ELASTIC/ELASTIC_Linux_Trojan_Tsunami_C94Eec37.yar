rule ELASTIC_Linux_Trojan_Tsunami_C94Eec37 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "c94eec37-8ae1-48d2-8c75-36f2582a2742"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "294fcdd57fc0a53e2d63b620e85fa65c00942db2163921719d052d341aa2dc30"
		logic_hash = "39a49e1661ac2ca6a43a56b0bd136976f6d506c0779d862a43ba2c25d6947fee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c692073af446327f739e1c81f4e3b56d812c00c556e882fe77bfdff522082db4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 05 88 10 8B 45 E4 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 E4 C6 40 }

	condition:
		all of them
}