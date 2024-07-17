import "dotnet"


rule EMBEERESEARCH_Win_Lumma_Simple_Strings : FILE
{
	meta:
		description = ""
		author = "Matthew @ Embee_Research"
		id = "d949d547-a2ee-56d9-8510-74f3b718b2c0"
		date = "2023-09-13"
		modified = "2023-09-21"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_lumma _simple_sep_2023.yar#L1-L40"
		license_url = "N/A"
		hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		logic_hash = "0b3cb6721d26b79afe892b1c4df5e54c18cd7a5492aeacd442deca6b9b926f3c"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Binedx765ance Chaedx765in Waledx765let" wide
		$s2 = "%appdaedx765ta%\\Moedx765zilla\\Firedx765efox\\Profedx765iles"
		$s3 = "\\Locedx765al Extensedx765ion Settinedx765gs\\"
		$s4 = "%appdedx765ata%\\Opedx765era Softwedx765are\\Opedx765era GX Staedx765ble"
		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and (( all of ($s*)) or ( all of ($o*)))
}