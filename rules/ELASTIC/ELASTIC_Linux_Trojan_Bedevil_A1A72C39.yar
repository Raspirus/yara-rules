rule ELASTIC_Linux_Trojan_Bedevil_A1A72C39 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bedevil (Linux.Trojan.Bedevil)"
		author = "Elastic Security"
		id = "a1a72c39-c8a3-4372-bd1d-de6360c9c19e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Bedevil.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "017a9d7290cf327444d23227518ab612111ca148da7225e64a9f6ebd253449ab"
		logic_hash = "227adcc340c38cebf56ea2f39b483c965dd46827d83afe5f866ca844c932da76"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ea4762d6ba0b88017feda1ed68d70bedd1438bb853b8ee1f83cbca2276bfbd1e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 3A 20 1B 5B 31 3B 33 31 6D 25 64 1B 5B 30 6D 0A 00 1B 5B }

	condition:
		all of them
}