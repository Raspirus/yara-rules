import "pe"


rule SIGNATURE_BASE_SUSP_Hxd_Icon_Anomaly_May23_1 : FILE
{
	meta:
		description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
		author = "Florian Roth"
		id = "3ac8cc92-6d76-5787-ada0-cfb6eabb4b20"
		date = "2023-05-29"
		modified = "2023-12-05"
		reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_file_anomalies.yar#L32-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a328687ac8b868fb78a49188b286a8951c6043a7ff6ff0c7a23c3f9b3ef15eb2"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
		$ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }
		$s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A }
		$s2 = "mh-nexus.de" ascii wide
		$upx1 = "UPX0" ascii fullword
		$xs1 = "terminator" ascii wide fullword
		$xs2 = "Terminator" ascii wide fullword

	condition:
		uint16(0)==0x5a4d and 1 of ($ac*) and ( not 1 of ($s*) or filesize >6930000 or (pe.is_32bit() and filesize <1540000 and not $upx1) or (pe.is_32bit() and filesize <590000 and $upx1) or (pe.is_64bit() and filesize <6670000 and not $upx1) or (pe.is_64bit() and filesize <1300000 and $upx1) or 1 of ($xs*))
}