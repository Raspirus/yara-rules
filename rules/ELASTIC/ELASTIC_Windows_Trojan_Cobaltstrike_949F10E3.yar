rule ELASTIC_Windows_Trojan_Cobaltstrike_949F10E3 : FILE MEMORY
{
	meta:
		description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
		author = "Elastic Security"
		id = "949f10e3-68c9-4600-a620-ed3119e09257"
		date = "2021-03-25"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L787-L806"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e4b726c83013f4b9c9d61683f78a4a91935225e9ed3de0ce164b96b5a6719579"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
		$a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }

	condition:
		all of them
}