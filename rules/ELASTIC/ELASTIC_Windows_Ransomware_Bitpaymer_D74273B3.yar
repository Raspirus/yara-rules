
rule ELASTIC_Windows_Ransomware_Bitpaymer_D74273B3 : BETA FILE MEMORY
{
	meta:
		description = "Identifies BITPAYMER ransomware"
		author = "Elastic Security"
		id = "d74273b3-d109-4b5d-beff-dffee9a984b1"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Bitpaymer.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "126246689b28e92ed10bfa6165f06ff7d4f0e062de7c58b821eaaf5e3cae9306"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "4f913f06f7c7decbeb78187c566674f91ebbf929ad7057641659bb756cf2991b"
		threat_name = "Windows.Ransomware.Bitpaymer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = { 24 E8 00 00 00 29 F0 19 F9 89 8C 24 88 00 00 00 89 84 24 84 00 }

	condition:
		1 of ($b*)
}