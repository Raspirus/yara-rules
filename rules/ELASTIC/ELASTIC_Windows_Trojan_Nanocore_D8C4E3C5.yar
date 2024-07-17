
rule ELASTIC_Windows_Trojan_Nanocore_D8C4E3C5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Nanocore (Windows.Trojan.Nanocore)"
		author = "Elastic Security"
		id = "d8c4e3c5-8bcc-43d2-9104-fa3774282da5"
		date = "2021-06-13"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Nanocore.yar#L1-L29"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b2262126a955e306dc68487333394dc08c4fbd708a19afeb531f58916ddb1cfd"
		logic_hash = "fcc13e834cd8a1f86b453fe3c0333cd358e129d6838a339a824f1a095d85552d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e5c284f14c1c650ef8ddd7caf314f5318e46a811addc2af5e70890390c7307d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "NanoCore.ClientPluginHost" ascii fullword
		$a2 = "NanoCore.ClientPlugin" ascii fullword
		$b1 = "get_BuilderSettings" ascii fullword
		$b2 = "ClientLoaderForm.resources" ascii fullword
		$b3 = "PluginCommand" ascii fullword
		$b4 = "IClientAppHost" ascii fullword
		$b5 = "GetBlockHash" ascii fullword
		$b6 = "AddHostEntry" ascii fullword
		$b7 = "LogClientException" ascii fullword
		$b8 = "PipeExists" ascii fullword
		$b9 = "IClientLoggingHost" ascii fullword

	condition:
		1 of ($a*) or 6 of ($b*)
}