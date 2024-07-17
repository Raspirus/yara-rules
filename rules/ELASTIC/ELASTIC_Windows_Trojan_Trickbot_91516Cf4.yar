
rule ELASTIC_Windows_Trojan_Trickbot_91516Cf4 : FILE MEMORY
{
	meta:
		description = "Generic signature used to identify Trickbot module usage"
		author = "Elastic Security"
		id = "91516cf4-c826-4d5d-908f-e1c0b3bccec5"
		date = "2021-03-30"
		modified = "2021-08-31"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L874-L896"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6cd0d4666553fd7184895502d48c960294307d57be722ebb2188b004fc1a8066"
		logic_hash = "6c0bdd6827bebb337c0012cdb6e931cd96ce2ad61f3764f288b96ff049b2d007"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2667c7181fb4db3f5765369fc2ec010b807a7bf6e2878fc42af410f036c61cbe"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<moduleconfig>" ascii wide
		$a2 = "<autostart>" ascii wide
		$a3 = "</autostart>" ascii wide
		$a4 = "</moduleconfig>" ascii wide

	condition:
		all of them
}