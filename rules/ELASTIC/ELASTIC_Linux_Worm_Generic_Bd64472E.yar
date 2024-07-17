rule ELASTIC_Linux_Worm_Generic_Bd64472E : FILE MEMORY
{
	meta:
		description = "Detects Linux Worm Generic (Linux.Worm.Generic)"
		author = "Elastic Security"
		id = "bd64472e-92a2-4d64-8008-b82d7ca33b1d"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Worm_Generic.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b3334a3b61b1a3fc14763dc3d590100ed5e85a97493c89b499b02b76f7a0a7d0"
		logic_hash = "9a7267a0ebc1073d0b1f81a61b963642cc816b563b43ff4d9508dd8bc195a0e1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1978baa7ff5457e06433fd45db098aefd39ea53d3f29e541eef54890a25a9dce"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C0 89 45 EC 83 7D EC FF 75 38 68 54 90 04 08 }

	condition:
		all of them
}