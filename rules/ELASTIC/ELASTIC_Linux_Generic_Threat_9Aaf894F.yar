rule ELASTIC_Linux_Generic_Threat_9Aaf894F : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "9aaf894f-d3f0-460d-82f8-831fecdf8b09"
		date = "2024-01-22"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L349-L367"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "467ac05956eec6c74217112721b3008186b2802af2cafed6d2038c79621bcb08"
		logic_hash = "b28d6a8c23aba4371e2e5f48861d2bcc8bdfa7212738eda7b1b4a3059d159cf2"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "15518c7e99ed1f39db2fe21578c08aadf8553fdb9cb44e4342bf117e613c6c12"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 2F 62 69 6E 2F 63 70 20 2F 74 6D 70 2F 70 61 6E 77 74 65 73 74 20 2F 75 73 72 2F 62 69 6E 2F 70 73 }

	condition:
		all of them
}