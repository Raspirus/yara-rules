
rule SIGNATURE_BASE_APT_CN_Twistedpanda_Loader : FILE
{
	meta:
		description = "Detects loader used by TwistedPanda"
		author = "Check Point Research"
		id = "a10f6019-f069-579c-b112-18537a7d8fd8"
		date = "2022-04-14"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_twisted_panda.yar#L1-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b6b3892432be4bd8dfd44f08c124865c54d5ad2dc90b630072f19f7144d33555"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "5b558c5fcbed8544cb100bd3db3c04a70dca02eec6fedffd5e3dcecb0b04fba0"
		hash2 = "efa754450f199caae204ca387976e197d95cdc7e83641444c1a5a91b58ba6198"

	strings:
		$seq1 = { 6A 40 68 00 30 00 00 }
		$seq2 = { 6A 00 50 6A 14 8D ?? ?? ?? ?? ?? 50 53 FF }
		$seq3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 80 }
		$decryption = { 8B C? [2-3] F6 D? 1A C? [2-3] [2-3] 30 0? ?? 4? }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and all of ($seq*) and $decryption
}