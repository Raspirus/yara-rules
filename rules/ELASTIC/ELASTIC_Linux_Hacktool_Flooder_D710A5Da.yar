
rule ELASTIC_Linux_Hacktool_Flooder_D710A5Da : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "d710a5da-26bf-4f6a-bf51-9cdac1f83aa3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L140-L158"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
		logic_hash = "118a29cc0ccd191181dabc134de282ba134e041113faaa4d95e0aa201646438b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e673aa8785c7076f4cced9f12b284a2927b762fe1066aba8d6a5ace775f3480c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 24 48 8B 45 E0 48 83 C0 10 48 8B 08 48 8B 45 E0 48 83 C0 08 48 }

	condition:
		all of them
}