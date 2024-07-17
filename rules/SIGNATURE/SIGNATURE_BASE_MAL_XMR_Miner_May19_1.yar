rule SIGNATURE_BASE_MAL_XMR_Miner_May19_1 : HIGHVOL FILE
{
	meta:
		description = "Detects Monero Crypto Coin Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "233d1d47-de67-55a9-ae7e-46b5dd34e6ce"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_nansh0u.yar#L15-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "85a65fd2355850b7f5261ad41091e181562938356ba3dae7d867f7ac8922a16e"
		score = 85
		quality = 85
		tags = "HIGHVOL, FILE"
		hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"

	strings:
		$x1 = "donate.ssl.xmrig.com" fullword ascii
		$x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$s1 = "[%s] login error code: %d" fullword ascii
		$s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and (pe.imphash()=="25d9618d1e16608cd5d14d8ad6e1f98e" or 1 of ($x*) or 2 of them )
}