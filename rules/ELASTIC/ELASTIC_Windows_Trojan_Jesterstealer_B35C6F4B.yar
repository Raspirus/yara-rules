rule ELASTIC_Windows_Trojan_Jesterstealer_B35C6F4B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Jesterstealer (Windows.Trojan.JesterStealer)"
		author = "Elastic Security"
		id = "b35c6f4b-995f-4336-94bf-fc6dc8c124f4"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_JesterStealer.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "10c3846867f70dd26c5a54332ed22070c9e5e0e4f52f05fdae12ead801f7933b"
		logic_hash = "acc49348267e963af9ff6ba7afa053d4056d4068b4386a872e33e025790ba759"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d91c26a06ba7c9330e38a4744299223d3b28a96f131bce5198c4ef7c74b7d2ff"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "[Decrypt Chrome Password] {0}" wide fullword
		$a2 = "Passwords.txt" wide fullword
		$a3 = "9Stealer.Recovery.FTP.FileZilla+<EnumerateCredentials>d__0" ascii fullword
		$a4 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A \"" wide fullword
		$a5 = "citigroup.com" wide fullword
		$a6 = "Password: {1}" wide fullword
		$a7 = "set_steamLogin" ascii fullword

	condition:
		5 of them
}