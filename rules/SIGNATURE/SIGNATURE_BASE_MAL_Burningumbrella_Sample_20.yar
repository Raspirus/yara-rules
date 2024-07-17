rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_20 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "1a39a76a-31e2-5d6e-82cb-ea38d503b6a9"
		date = "2018-05-04"
		modified = "2023-01-06"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L334-L355"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e2739a89451a4eba0bae345203dd4c0e26f715bb079830e36c772861fdd0f4de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5c12379cd7ab3cb03dac354d0e850769873d45bb486c266a893c0daa452aa03c"
		hash2 = "172cd90fd9e31ba70e47f0cc76c07d53e512da4cbfd197772c179fe604b75369"
		hash3 = "1ce88e98c8b37ea68466657485f2c01010a4d4a88587ba0ae814f37680a2e7a8"

	strings:
		$s1 = "Wordpad.Document.1\\shell\\open\\command\\" wide
		$s2 = "%s\\shell\\Open\\command" fullword wide
		$s3 = "expanding computer" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="bac338bfe2685483c201e15eae4352d5" or 2 of them )
}