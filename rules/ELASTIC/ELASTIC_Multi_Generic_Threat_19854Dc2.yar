rule ELASTIC_Multi_Generic_Threat_19854Dc2 : FILE MEMORY
{
	meta:
		description = "Detects Multi Generic Threat (Multi.Generic.Threat)"
		author = "Elastic Security"
		id = "19854dc2-a568-4f6c-bd47-bcae9976c66f"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Generic_Threat.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "be216fa9cbf0b64d769d1e8ecddcfc3319c7ca8e610e438dcdfefc491730d208"
		logic_hash = "beed6d6cd7b7b6eb3f4ab6a45fd19f2ebfb661e470d468691b68634994e2eef7"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "64d3803490fa71f720678ca2989cc698ea9b1a398d02d6d671fa01e0ff42f8b5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = { 26 2A 73 74 72 75 63 74 20 7B 20 45 6E 74 72 79 53 61 6C 74 20 5B 5D 75 69 6E 74 38 3B 20 4C 65 6E 20 69 6E 74 20 7D }

	condition:
		all of them
}