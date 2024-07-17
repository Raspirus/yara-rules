
rule SIGNATURE_BASE_MAL_ELF_Vpnfilter_3 : FILE
{
	meta:
		description = "Detects VPNFilter malware"
		author = "Florian Roth (Nextron Systems)"
		id = "020603bf-fbce-5de1-82b9-5a2dfacfada3"
		date = "2018-05-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_vpnfilter.yar#L50-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "71152b57f2d6040608febf32441e1899fdf2479335c26c1143ea58759e6d9094"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92"
		hash2 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
		hash3 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
		hash4 = "0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b"
		hash5 = "4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b"
		hash6 = "8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1"
		hash7 = "776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d"

	strings:
		$sx1 = "User-Agent: Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)" fullword ascii
		$sx2 = "Execute by shell[%d]:" fullword ascii
		$sx3 = "CONFIG.TOR.name:" fullword ascii
		$s1 = "Executing command:  %s %s..." fullword ascii
		$s2 = "/proc/%d/cmdline" fullword ascii
		$a1 = "Mozilla/5.0 Firefox/50.0" fullword ascii
		$a2 = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
		$a3 = "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <1000KB and (1 of ($sx*) or 2 of ($s*) or 2 of ($a*))
}