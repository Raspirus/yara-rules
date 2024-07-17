rule ELASTIC_Windows_Trojan_Flawedgrace_8C5Eb04B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Flawedgrace (Windows.Trojan.FlawedGrace)"
		author = "Elastic Security"
		id = "8c5eb04b-301b-4d05-a010-3329e5b764c6"
		date = "2023-11-01"
		modified = "2023-11-02"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_FlawedGrace.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "966112f3143d751a95c000a990709572ac8b49b23c0e57b2691955d6fda1016e"
		logic_hash = "dc07197cb9a02ff8d271f78756c2784c74d09e530af20377a584dbfe77e973aa"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "46ce025974792cdefe9d4f4493cee477c0eaf641564cd44becd687c27d9e7c30"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Grace finalized, no more library calls allowed." ascii fullword
		$a2 = ".?AVReadThread@TunnelIO@NS@@" ascii fullword
		$a3 = ".?AVTunnelClientDirectIO@NS@@" ascii fullword
		$a4 = ".?AVWireClientConnectionThread@NS@@" ascii fullword
		$a5 = ".?AVWireParam@NS@@" ascii fullword

	condition:
		3 of them
}