rule SIGNATURE_BASE_HKTL_Htran_Go : FILE
{
	meta:
		description = "Detects go based htran variant"
		author = "Jeff Beley"
		id = "bd9409e3-3d4c-57d6-af60-b6d6bd93d46b"
		date = "2019-01-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4604-L4617"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "444fe8ce2fdb67c982de26a10882d2cfebc4d2de6c4b4ba6ee10cf39130f1cc5"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "4acbefb9f7907c52438ebb3070888ddc8cddfe9e3849c9d0196173a422b9035f"

	strings:
		$s1 = "https://github.com/cw1997/NATBypass" fullword ascii
		$s2 = "-slave ip1:port1 ip2:port2" fullword ascii
		$s3 = "-tran port1 ip:port2" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <7000KB and 1 of them
}