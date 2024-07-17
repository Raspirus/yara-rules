rule ELASTIC_Windows_Trojan_Agenttesla_E577E17E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Agenttesla (Windows.Trojan.AgentTesla)"
		author = "Elastic Security"
		id = "e577e17e-5c42-4431-8c2d-0c1153128226"
		date = "2022-03-11"
		modified = "2022-04-12"
		reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_AgentTesla.yar#L60-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
		logic_hash = "84c5f1096735cee0f0f4ad41a81286c0a60dc17c276f23568b855271d996c8a2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }

	condition:
		all of them
}