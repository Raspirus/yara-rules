rule ELASTIC_Windows_Trojan_Metasploit_66140F58 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Metasploit (Windows.Trojan.Metasploit)"
		author = "Elastic Security"
		id = "66140f58-1815-4e21-8544-24fed74194f1"
		date = "2022-08-15"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Metasploit.yar#L270-L288"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01a0c5630fbbfc7043d21a789440fa9dadc6e4f79640b370f1a21c6ebf6a710a"
		logic_hash = "0a855b7296f7cea39cc5d57b239d3906133ea43a0811ec60e4d91765cf89aced"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "79879b2730e98f3eddeca838dff438d75a43ac20c0da6a4802474ff05f9cc7a3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }

	condition:
		all of them
}