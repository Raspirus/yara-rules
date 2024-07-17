rule ELASTIC_Macos_Trojan_Metasploit_293Bfea9 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Metasploit (MacOS.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L21-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
		logic_hash = "b8bd0d034a6306f99333723d77724ae53c1a189dad3fad7417f2d2fde214c24a"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "_webcam_get_frame" ascii fullword
		$a2 = "_get_process_info" ascii fullword
		$a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
		$a4 = "Dumping cert info:" ascii fullword

	condition:
		all of them
}