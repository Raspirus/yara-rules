
rule ELASTIC_Linux_Trojan_Generic_C3D529A2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "c3d529a2-f2c7-41de-ba2a-2cbf2eb4222c"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L281-L299"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b46135ae52db6399b680e5c53f891d101228de5cd6c06b6ae115e4a763a5fb22"
		logic_hash = "a508acd95844a4385943166f715606199048d96be0098bc89f9be7b9db34833e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "72ef5b28489e01c3f2413b9a907cda544fc3f60e00451382e239b55ec982f187"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 1C 31 C0 5B 5E 5F 5D C3 8B 1C 24 C3 8D 64 24 04 53 8B DA 5B }

	condition:
		all of them
}