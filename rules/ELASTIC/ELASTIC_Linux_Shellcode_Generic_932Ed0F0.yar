rule ELASTIC_Linux_Shellcode_Generic_932Ed0F0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Shellcode Generic (Linux.Shellcode.Generic)"
		author = "Elastic Security"
		id = "932ed0f0-bd43-4367-bcc3-ecd8f65b52ee"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Shellcode_Generic.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f357597f718f86258e7a640250f2e9cf1c3363ab5af8ddbbabb10ebfa3c91251"
		logic_hash = "20ae3f1d96f8afd0900ac919eacaff3bd748a7466af5bb2b9f77cfdc4b8b829e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7aa4619d2629b5d795e675d17a6e962c6d66a75e11fa884c0b195cb566090070"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E3 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}