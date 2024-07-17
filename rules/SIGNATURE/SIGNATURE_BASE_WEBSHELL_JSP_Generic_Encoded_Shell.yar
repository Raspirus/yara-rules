rule SIGNATURE_BASE_WEBSHELL_JSP_Generic_Encoded_Shell : FILE
{
	meta:
		description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "359949d7-1793-5e13-9fdc-fe995ae12117"
		date = "2021-01-07"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_webshells.yar#L6145-L6171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
		hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
		hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
		logic_hash = "74f45478e5bd7bb300e4ec493c2d3ef9a26340a141c3512a722618b3a3731500"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$sj0 = /\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
		$sj1 = /\{ ?99, 109, 100}/ wide ascii
		$sj2 = /\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
		$sj3 = /\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
		$sj4 = /\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
		$sj5 = /\{ ?101, 120, 101, 99 }/ wide ascii
		$sj6 = /\{ ?103, 101, 116, 82, 117, 110/ wide ascii

	condition:
		filesize <300KB and any of ($sj*)
}