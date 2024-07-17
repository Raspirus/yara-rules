rule SIGNATURE_BASE_PUA_WIN_XMRIG_Cryptocoin_Miner_Dec20 : FILE
{
	meta:
		description = "Detects XMRIG crypto coin miners"
		author = "Florian Roth (Nextron Systems)"
		id = "4dfb04e9-fbba-5a6f-ad20-d805025d2d74"
		date = "2020-12-31"
		modified = "2023-12-05"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_crypto_miner.yar#L19-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c39aee669a98bcc9d07821aef248096e45a6c54ab22b8b98c0a393b445f3934e"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "b6154d25b3aa3098f2cee790f5de5a727fc3549865a7aa2196579fe39a86de09"

	strings:
		$x1 = "xmrig.exe" fullword wide
		$x2 = "xmrig.com" fullword wide
		$x3 = "* for x86, CRYPTOGAMS" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and 2 of them or all of them
}