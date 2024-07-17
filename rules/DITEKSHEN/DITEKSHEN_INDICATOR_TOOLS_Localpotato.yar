import "pe"


rule DITEKSHEN_INDICATOR_TOOLS_Localpotato : FILE
{
	meta:
		description = "Detects LocalPotato"
		author = "ditekShen"
		id = "65f8305b-b830-58e7-970b-da1df9a06e9b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1776-L1807"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "88fba16a6eec6d2c23331642041c6adfddddeb21ba8e74b6959bd48c90f73cbb"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$x1 = "LocalPotato.stg" fullword wide
		$x2 = "we always love potatoes" fullword ascii
		$s1 = "{00000306-0000-0000-c000-000000000046}" wide
		$s2 = "{854A20FB-2D44-457D-992F-EF13785D2B51}" wide
		$s3 = "cifs/127.0.0.1" wide
		$s4 = "\\\\127.0.0.1\\c$" wide
		$s5 = "complete failed: 0x%08x" ascii
		$s6 = "Authorization: NTLM %s" ascii
		$s7 = "Objref Moniker Display Name = %S" ascii
		$s8 = "SMB Connect Tree: %S" ascii
		$s9 = "b64type=%s" fullword ascii
		$s10 = "decodes=%s" fullword ascii
		$s11 = { 53 4d 42 72 00 00 00 00 18 01 48 00 00 00 00 00
               00 00 00 00 00 00 00 ff ff ac 7b 00 00 00 00 00
               22 00 02 4e 54 20 4c 4d 20 30 2e 31 32 00 02 53
               4d 42 20 32 2e 30 30 32 00 02 53 4d 42 20 32 2e
               3f 3f 3f 00 00 00 00 00 00 00 00 00 00 00 68 fe
               53 4d 42 40 }
		$o1 = { 44 8b 4c 24 34 48 8d 44 24 38 48 89 44 24 28 4c }
		$o2 = { e8 c4 ff ff ff 33 d2 48 8d 4d f0 41 b8 d0 04 00 }
		$o3 = { 83 7b 0c 00 75 42 8b 03 25 ff ff ff 1f 3d 21 05 }
		$o4 = { 3c 68 74 6c 3c 6a 74 5c 3c 6c 74 34 3c 74 74 24 }
		$o5 = { e9 39 ff ff ff cc 48 89 5c 24 08 4c 89 4c 24 20 }
		$o6 = { 48 b9 ff ff ff ff ff ff 0f 00 48 8b c2 41 b8 0c }

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 5 of ($s*)) or 8 of ($s*) or (4 of ($o*) and (1 of ($x*) or 5 of ($s*))))
}