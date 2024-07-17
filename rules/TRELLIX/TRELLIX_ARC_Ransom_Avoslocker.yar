rule TRELLIX_ARC_Ransom_Avoslocker : FILE
{
	meta:
		description = "Rule to detect Avoslocker Ransomware"
		author = "CB @ ATR"
		id = "50f029c8-154e-583d-8264-8d86d01075f6"
		date = "2021-07-22"
		modified = "2021-07-22"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Avoslocker.yar#L3-L27"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "316aaab225797eedd62f9cfde1fdbd799a10441b3b15a8abc76141b57b36b1d3"
		score = 75
		quality = 70
		tags = "FILE"
		Version = "v1"
		DetectionName = "Ransom_Win_Avoslocker"
		hash1 = "fb544e1f74ce02937c3a3657be8d125d5953996115f65697b7d39e237020706f"
		hash2 = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"

	strings:
		$v1 = "CryptImportPublicKeyInfo failed. error: %d" fullword ascii
		$v2 = "CryptStringToBinary failed. Err: %d" fullword ascii
		$v3 = "encrypting %ls failed" fullword wide
		$v4 = "CryptDecodeObjectEx 1 failed. Err: %p" fullword ascii
		$v5 = "operator co_await" fullword ascii
		$v6 = "drive %s took %f seconds" fullword ascii
		$seq0 = { 8d 4e 04 5e e9 b1 ff ff ff 55 8b ec ff 75 08 ff }
		$seq1 = { 33 c0 80 fb 2d 0f 94 c0 05 ff ff ff 7f eb 02 f7 }
		$seq2 = { 8b 40 0c 89 85 1c ff ff ff 8b 40 0c 89 85 18 ff }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and pe.imphash()=="a24c2b5bf84a5465eb75f1e6aa8c1eec" and (5 of them ) and all of ($seq*)) or ( all of them )
}