rule ELASTIC_Linux_Shellcode_Generic_99B991Cd : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "99b991cd-a5ca-475c-8c10-e43b9d22d26e"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "954b5a073ce99075b60beec72936975e48787bea936b4c5f13e254496a20d81d"
		logic_hash = "664e213314fe1d6f1920de237ebea3a94f7fbc42eff089475674ccef812f0f68"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ed904a3214ccf43482e3ddf75f3683fea45f7c43a2f1860bac427d7d15d8c399"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6E 89 E3 50 53 89 E1 B0 0B CD 80 00 4C 65 6E 67 }

	condition:
		all of them
}