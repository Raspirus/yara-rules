rule ELASTIC_Linux_Webshell_Generic_E80Ff633 : FILE MEMORY
{
	meta:
		description = "Detects Linux Webshell Generic (Linux.Webshell.Generic)"
		author = "Elastic Security"
		id = "e80ff633-990e-4e2e-ac80-2e61685ab8b0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Webshell_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7640ba6f2417931ef901044152d5bfe1b266219d13b5983d92ddbdf644de5818"
		logic_hash = "d345e6ce3e51ed55064aafb1709e9bee7ef2ce87ec80165ac1b58eebd83cefee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dcca52dce2d50b0aa6cf0132348ce9dc234b985ae683b896d9971d409f109849"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 A8 00 00 00 89 1C 24 83 3C 24 00 74 23 83 04 24 24 8D B4 24 AC 00 }

	condition:
		all of them
}