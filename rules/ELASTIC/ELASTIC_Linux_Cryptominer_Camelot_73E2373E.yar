rule ELASTIC_Linux_Cryptominer_Camelot_73E2373E : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "73e2373e-75ac-4385-b663-a50423626fc8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L138-L156"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
		logic_hash = "2377da6667860dc7204760ee64213cba95909c9181bd1a3ea96c3ad29988c9f7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6ce73e55565e9119a355b91ec16c2147cc698b1a57cc29be22639b34ba39eea9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 48 83 7D F8 00 74 4D 48 8B 55 80 48 8D 45 A0 48 89 D6 48 }

	condition:
		all of them
}