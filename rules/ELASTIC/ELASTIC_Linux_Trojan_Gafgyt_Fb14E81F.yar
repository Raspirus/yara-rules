rule ELASTIC_Linux_Trojan_Gafgyt_Fb14E81F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "fb14e81f-be2a-4428-9877-958e394a7ae2"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "0fd07e6068a721774716eb4940e2c19faef02d5bdacf3b018bf5995fa98a3a27"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1307-L1325"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2efb958c269640c374485502611372f4404cf35d7ab704d20ce37b8c1f69645d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "12b430108256bd0f57f48b9dbbea12eba7405c0b3b66a1c4b882647051f1ec52"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4E 45 52 00 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 }

	condition:
		all of them
}