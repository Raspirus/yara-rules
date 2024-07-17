import "pe"


rule DITEKSHEN_INDICATOR_TOOL_ENC_Diskcryptor : FILE
{
	meta:
		description = "Detect DiskCryptor open encryption solution that offers encryption of all disk partitions"
		author = "ditekSHen"
		id = "22b25d5c-d67f-53ac-9ae8-2de077afdda9"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1209-L1232"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "7ef0bf3b11f7e4055908518ce5b6a49e04d7002ebc3396fd2da32b4e13cf68e0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "\\DiskCryptor\\DCrypt\\" ascii
		$s1 = "Error getting %sbootloader configuration" fullword wide
		$s2 = "loader.iso" fullword wide
		$s3 = "Bootloader config for [%s]" fullword wide
		$s4 = "dc_get_mbr_config" fullword ascii
		$s5 = "dc_encrypt_iso_image" fullword ascii
		$s6 = "dc_start_re_encrypt" fullword ascii
		$s7 = "dc_start_encrypt" fullword ascii
		$s8 = "_w10_reflect_" ascii
		$d1 = "\\DosDevices\\dcrypt" fullword wide
		$d2 = "$dcsys$_fail_%x" fullword wide
		$d3 = "%s\\$DC_TRIM_%x$" fullword wide
		$d4 = "\\Device\\dcrypt" fullword wide
		$d5 = "%s\\$dcsys$" fullword wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 2 of ($s*)) or 4 of ($s*) or 3 of ($d*))
}