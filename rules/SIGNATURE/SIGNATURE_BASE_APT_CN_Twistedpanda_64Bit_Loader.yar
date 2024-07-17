rule SIGNATURE_BASE_APT_CN_Twistedpanda_64Bit_Loader : FILE
{
	meta:
		description = "Detects the 64bit Loader DLL used by TwistedPanda"
		author = "Check Point Research"
		id = "2172dd33-204b-5a05-ad26-534a0c1d7a17"
		date = "2022-04-14"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_twisted_panda.yar#L120-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "644547f9fa6ca3f34ea32e06896f341e0c92f5c57dee3c478aed0cdf87b2f3de"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "e0d4ef7190ff50e6ad2a2403c87cc37254498e8cc5a3b2b8798983b1b3cdc94f"

	strings:
		$path_check = { 48 8D [6] 48 8B ?? 48 81 [5] 72 }
		$shellcode_read = { 48 8B D0 41 B8 F0 16 00 00 48 8B CF 48 8B D8 FF}
		$shellcode_allocate = { BA F0 16 00 00 44 8D 4E 40 33 C9 41 B8 00 30 00 00 FF }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and $path_check and $shellcode_allocate and $shellcode_read
}