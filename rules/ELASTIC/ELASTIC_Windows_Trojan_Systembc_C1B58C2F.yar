
rule ELASTIC_Windows_Trojan_Systembc_C1B58C2F : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Systembc (Windows.Trojan.SystemBC)"
		author = "Elastic Security"
		id = "c1b58c2f-8bbf-4c03-9f53-13ab2fb081cc"
		date = "2024-05-02"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SystemBC.yar#L26-L49"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "016fc1db90d9d18fe25ed380606346ef12b886e1db0d80fe58c22da23f6d677d"
		logic_hash = "16ed14dac0c30500c5e91759b0a1b321f3bd53ae6aab1389a685582eba72c222"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dfbf98554e7fb8660e4eebd6ad2fadc394fc2a4168050390370ec358f6af1c1d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "GET %s HTTP/1.0" ascii fullword
		$a2 = "HOST1:"
		$a3 = "PORT1:"
		$a4 = "-WindowStyle Hidden -ep bypass -file \"" ascii fullword
		$a5 = "BEGINDATA" ascii fullword
		$a6 = "socks32.dll" ascii fullword

	condition:
		5 of them
}