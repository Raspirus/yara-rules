rule ELASTIC_Windows_Trojan_Cobaltstrike_A3Fb2616 : FILE MEMORY
{
	meta:
		description = "Rule for browser pivot "
		author = "Elastic Security"
		id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
		date = "2021-10-21"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L925-L947"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		logic_hash = "a3c36326ccc2bc828f6654ccaba507a283f92146fdc52f71d7d934f6908793e2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "browserpivot.dll" ascii fullword
		$a2 = "browserpivot.x64.dll" ascii fullword
		$b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
		$b2 = "COBALTSTRIKE" ascii fullword

	condition:
		1 of ($a*) and 2 of ($b*)
}