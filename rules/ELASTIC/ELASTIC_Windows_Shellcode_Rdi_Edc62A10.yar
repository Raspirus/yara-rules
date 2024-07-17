rule ELASTIC_Windows_Shellcode_Rdi_Edc62A10 : FILE MEMORY
{
	meta:
		description = "Detects Windows Shellcode Rdi (Windows.Shellcode.Rdi)"
		author = "Elastic Security"
		id = "edc62a10-7cb1-4fda-a15c-86d40d510ffd"
		date = "2023-06-23"
		modified = "2023-07-10"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Shellcode_Rdi.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "64485ffc283e981c8b77db5a675c7ba2a04d3effaced522531185aa46eb6a36b"
		logic_hash = "986cb6c28d2d9767a2fd084fdd71edb7a1c36e78ddedf3c562076cf6f5b5afd1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1cee85457eb31be126a41d4e332735957cf4a928fdf4b5253380b6c97605d069"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA [10] 00 41 B9 04 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 }

	condition:
		all of them
}