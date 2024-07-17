
rule ELASTIC_Linux_Trojan_Kaiji_253C44De : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Kaiji (Linux.Trojan.Kaiji)"
		author = "Elastic Security"
		id = "253c44de-3f48-49f9-998d-1dec2981108c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Kaiji.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e31eb8880bb084b4c642eba127e64ce99435ea8299a98c183a63a2e6a139d926"
		logic_hash = "81a07f60765f50c58b2c0f0153367ee570f36c579e9f88fb2f0e49ae5c08773f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f390a16ca4270dc38ce1a52bbdc1ac57155f369a74005ff2a4e46c6d043b869e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EB 27 0F B6 1C 10 48 8B 74 24 40 48 8B BC 24 90 00 00 00 88 }

	condition:
		all of them
}