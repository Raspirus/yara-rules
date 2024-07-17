
rule ELASTIC_Linux_Trojan_Gafgyt_A473Dcb6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "a473dcb6-887e-4a9a-a1f2-df094f1575b9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L435-L453"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7ba74e3cb0d633de0e8dbe6cfc49d4fc77dd0c02a5f1867cc4a1f1d575def97d"
		logic_hash = "106ee9cd9c368674ae08b835f54dbb6918b553e3097aae9b0de88f55420f046b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6119a43aa5c9f61249083290293f15696b54b012cdf92553fd49736d40c433f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 49 56 04 0B 1E 46 1E B0 EB 10 18 38 38 D7 80 4D 2D 03 29 62 }

	condition:
		all of them
}