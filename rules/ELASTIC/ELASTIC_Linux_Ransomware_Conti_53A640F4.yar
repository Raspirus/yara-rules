rule ELASTIC_Linux_Ransomware_Conti_53A640F4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Conti (Linux.Ransomware.Conti)"
		author = "Elastic Security"
		id = "53a640f4-905c-4b0d-ac4a-9ffdffd74253"
		date = "2022-09-22"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Conti.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
		logic_hash = "b83a47664d8acce7de17ac5972d9fd5e708c8cd3d8ebedc2bacf1397fd25f5d3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d81309f83494b0635444234c514fda0edc05a11ac861c769a007f9f558def148"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 D3 EA 48 89 D0 83 E0 01 48 85 C0 0F 95 C0 84 C0 74 0B 8B }

	condition:
		all of them
}