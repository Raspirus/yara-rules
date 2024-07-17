
rule ELASTIC_Linux_Cryptominer_Xmrminer_2Dd045Fc : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "2dd045fc-a585-4a49-b334-773bc86a3370"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L159-L177"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "30a77ab582f0558829a78960929f657a7c3c03c2cf89cd5a0f6934b79a74b7a4"
		logic_hash = "fa23ca75027f7a5e73652173c9e84112a0b5cd3008fc453fdb33c980dc7b7b24"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b5f02ac76db686e61c6f293183f2c17fe0f901a65eebaccfe109f07fc9abeeaa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { BA 0E 00 00 00 74 25 48 8B 8C 24 B8 00 00 00 64 48 33 0C 25 28 00 }

	condition:
		all of them
}