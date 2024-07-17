rule TRELLIX_ARC_Trojan_Coinminer : FILE
{
	meta:
		description = "Rule to detect Coinminer malware"
		author = "Trellix ATR"
		id = "ec1f4fb7-bce3-5d5b-bbff-50f9bfc90298"
		date = "2021-07-22"
		modified = "2022-01-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/miners/Trojan_CoinMiner.yar#L3-L23"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "0d9d502eb0a54f90044f42f8ce485a2df6814064172cb7bf006a8c8a51976acd"
		score = 75
		quality = 70
		tags = "FILE"
		version = "v1"
		hash1 = "3bdac08131ba5138bcb5abaf781d6dc7421272ce926bc37fa27ca3eeddcec3c2"
		hash2 = "d60766c4e6e77de0818e59f687810f54a4e08505561a6bcc93c4180adb0f67e7"

	strings:
		$seq0 = { df 75 ab 7b 80 bf 83 c1 48 b3 18 74 70 01 24 5c }
		$seq1 = { 08 37 4e 6e 0f 50 0b 11 d0 98 0f a8 b8 27 47 4e }
		$seq2 = { bf 17 5a 08 09 ab 80 2f a1 b0 b1 da 47 9f e1 61 }
		$seq3 = { 53 36 34 b2 94 01 cc 05 8c 36 aa 8a 07 ff 06 1f }
		$seq4 = { 25 30 ae c4 44 d1 97 82 a5 06 05 63 07 02 28 3a }
		$seq5 = { 01 69 8e 1c 39 7b 11 56 38 0f 43 c8 5f a8 62 d0 }

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and pe.imphash()=="e4290fa6afc89d56616f34ebbd0b1f2c" and 3 of ($seq*))
}