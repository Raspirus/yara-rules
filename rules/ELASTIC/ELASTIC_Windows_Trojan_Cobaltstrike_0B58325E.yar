
rule ELASTIC_Windows_Trojan_Cobaltstrike_0B58325E : FILE MEMORY
{
	meta:
		description = "Identifies Keylogger module from Cobalt Strike"
		author = "Elastic Security"
		id = "0b58325e-2538-434d-9a2c-26e2c32db039"
		date = "2021-03-23"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L39-L77"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "3822431e946fcc38c700cc8ce213e95f33a155d7f38b6ab2a24cb998d42c8521"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "keylogger.dll" ascii fullword
		$a2 = "keylogger.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\keylogger" ascii fullword
		$a4 = "%cE=======%c" ascii fullword
		$a5 = "[unknown: %02X]" ascii fullword
		$b1 = "ReflectiveLoader"
		$b2 = "%c2%s%c" ascii fullword
		$b3 = "[numlock]" ascii fullword
		$b4 = "%cC%s" ascii fullword
		$b5 = "[backspace]" ascii fullword
		$b6 = "[scroll lock]" ascii fullword
		$b7 = "[control]" ascii fullword
		$b8 = "[left]" ascii fullword
		$b9 = "[page up]" ascii fullword
		$b10 = "[page down]" ascii fullword
		$b11 = "[prtscr]" ascii fullword
		$b12 = "ZRich9" ascii fullword
		$b13 = "[ctrl]" ascii fullword
		$b14 = "[home]" ascii fullword
		$b15 = "[pause]" ascii fullword
		$b16 = "[clear]" ascii fullword

	condition:
		1 of ($a*) and 14 of ($b*)
}