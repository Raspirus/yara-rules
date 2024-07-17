rule ELASTIC_Linux_Trojan_Dropperl_B97Baf37 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "b97baf37-48db-4eb7-85c7-08e75054bea7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
		logic_hash = "e58130c33242bc3020602c2c0254bed2bbc564c4a11806c6cfcd858fd724c362"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0852f1afa6162d14b076a3fc1f56e4d365b5d0e8932bae6ab055000cca7d1fba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 12 48 89 10 83 45 DC 01 83 45 D8 01 8B 45 D8 3B 45 BC 7C CF 8B }

	condition:
		all of them
}