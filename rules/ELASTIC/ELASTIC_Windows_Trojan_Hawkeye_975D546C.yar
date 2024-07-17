rule ELASTIC_Windows_Trojan_Hawkeye_975D546C : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Hawkeye (Windows.Trojan.Hawkeye)"
		author = "Elastic Security"
		id = "975d546c-286b-4753-b894-d6ed0aa832f3"
		date = "2023-03-23"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Hawkeye.yar#L25-L48"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "aca133bf1d72cf379101e6877871979d6e6e8bc4cc692a5ba815289735014340"
		logic_hash = "cbd8ce991059f961236a4bb83ea5a78efa661199b40fca8b09550856e932198b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5bbdb07fa6dd3e415f49d7f4fbc249c078ae42ebd81cad3015e32dfdc8f7cda6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "api.telegram.org"
		$s2 = "Browsers/Passwords"
		$s3 = "Installed Browsers.txt"
		$s4 = "Browsers/AutoFills"
		$s5 = "Passwords.txt"
		$s6 = "System Information.txt"

	condition:
		all of them
}