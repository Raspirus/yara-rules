rule SIGNATURE_BASE_XMRIG_Monero_Miner : HIGHVOL FILE
{
	meta:
		description = "Detects Monero mining software"
		author = "Florian Roth (Nextron Systems)"
		id = "71bf1b9c-c806-5737-83a9-d6013872b11d"
		date = "2018-01-04"
		modified = "2022-11-10"
		reference = "https://github.com/xmrig/xmrig/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_xmrig_monero_miner.yar#L11-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "532e602dfc8e44326e381d0e2a189b60bc4d4f2b310169767b2326e01606a542"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
		hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
		hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
		hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"

	strings:
		$s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$s2 = "--cpu-affinity" ascii
		$s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
		$s4 = "password for mining server" fullword ascii
		$s5 = "XMRig/%s libuv/%s%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and filesize <10MB and 2 of them
}