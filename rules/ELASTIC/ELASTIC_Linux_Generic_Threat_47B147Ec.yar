rule ELASTIC_Linux_Generic_Threat_47B147Ec : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "47b147ec-bcd2-423a-bc67-a85712d135eb"
		date = "2024-02-01"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L470-L488"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cc7734a10998a4878b8f0c362971243ea051ce6c1689444ba6e71aea297fb70d"
		logic_hash = "84c68f2ed76d644122daf81d41d4eb0be9aa8b1c82993464d3138ae30992110f"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "38f55b825bbd1fa837b2b9903d01141a071539502fe21b874948dbc5ac215ae8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 50 41 54 48 3D 2F 62 69 6E 3A 2F 73 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 75 73 72 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 62 69 6E 3A 2F 75 73 72 2F 6C 6F 63 61 6C 2F 73 62 69 6E }

	condition:
		all of them
}