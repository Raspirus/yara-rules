rule ELASTIC_Linux_Cryptominer_Malxmr_Bcab1E8F : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Malxmr (Linux.Cryptominer.Malxmr)"
		author = "Elastic Security"
		id = "bcab1e8f-8a8f-4309-8e47-416861d1894c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Malxmr.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "19df7fd22051abe3f782432398ea30f8be88cf42ef14bc301b1676f35b37cd7e"
		logic_hash = "72643b2860f40c7e901c671d7cc9992870b91912df5d75d2ffba0dfb8684f8d3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2106f2ba97c75468a2f25d1266053791034ff9a15d57df1ba3caf21f74b812f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EB D9 D3 0B EB D5 29 0B EB D1 03 48 6C 01 0B EB CA 0F AF 0B }

	condition:
		all of them
}