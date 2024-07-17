
rule CAPE_Lumma : FILE
{
	meta:
		description = "Lumma Payload"
		author = "kevoreilly"
		id = "334807ca-8548-5219-8614-7c922368e276"
		date = "2024-03-13"
		modified = "2024-03-13"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Lumma.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "5b172496e2488cc3e9cdbd5a08229c3691bafba2fcdbdfd2805c7ac58f9c5751"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Lumma Payload"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"

	strings:
		$c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
		$peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
		$remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

	condition:
		uint16(0)==0x5a4d and any of them
}