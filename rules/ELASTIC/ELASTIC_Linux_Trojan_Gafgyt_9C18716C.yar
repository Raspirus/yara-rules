rule ELASTIC_Linux_Trojan_Gafgyt_9C18716C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "9c18716c-e5cd-4b4f-98e2-0daed77f34cd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L257-L274"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "0e70dc82b2049a6f5efcc501e18e6f87e04a2d50efcb5143240c68c4a924de52"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "351772d2936ec1a14ee7e2f2b79a8fde62d02097ae6a5304c67e00ad1b11085a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FC 80 F6 FE 59 21 EC 75 10 26 CF DC 7B 5A 5B 4D 24 C9 C0 F3 }

	condition:
		all of them
}