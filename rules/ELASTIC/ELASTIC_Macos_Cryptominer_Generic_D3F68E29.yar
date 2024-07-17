rule ELASTIC_Macos_Cryptominer_Generic_D3F68E29 : FILE MEMORY
{
	meta:
		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "d3f68e29-830d-4d40-a285-ac29aed732fa"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Cryptominer_Generic.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
		logic_hash = "cc336e536e0f8dda47f9551dfabfc50c2094fffe4a69cdcec23824dd063dede0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
		$a2 = "Ethminer - GPU ethash miner" ascii fullword
		$a3 = "StratumClient"

	condition:
		all of them
}