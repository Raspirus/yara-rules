rule SIGNATURE_BASE_APT_APT41_HIGHNOON_BIN : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON.BIN"
		author = "Florian Roth (Nextron Systems)"
		id = "c8bd62b4-b882-5c04-aace-76dd4a21a784"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L159-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c6557bff952454482271d1b52fb37b2dd0471abd237449fd9c94b293ea5218b3"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
		hash2 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"

	strings:
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "\\Device\\PORTLESS_DeviceName" wide
		$s3 = "%s%s\\Security" fullword ascii
		$s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
		$s5 = "%s%s\\Enum" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="b70358b00dd0138566ac940d0da26a03" or 3 of them )
}