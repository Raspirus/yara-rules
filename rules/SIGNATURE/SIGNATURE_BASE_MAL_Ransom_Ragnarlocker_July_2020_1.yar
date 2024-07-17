import "pe"


rule SIGNATURE_BASE_MAL_Ransom_Ragnarlocker_July_2020_1 : FILE
{
	meta:
		description = "Detects Ragnarlocker by strings (July 2020)"
		author = "Arkbird_SOLG"
		id = "60e09057-d9f8-5e89-8f47-c5dda32806c6"
		date = "2020-07-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/JAMESWT_MHT/status/1288797666688851969"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ransom_ragna_locker.yar#L38-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dc44da2f9023e0702afa8081e85ba817ebfde15f449261fae9de729d51262b04"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "04c9cc0d1577d5ee54a4e2d4dd12f17011d13703cdd0e6efd46718d14fd9aa87"

	strings:
		$f1 = "bootfont.bin" fullword wide
		$f2 = "bootmgr.efi" fullword wide
		$f3 = "bootsect.bak" fullword wide
		$r1 = "$!.txt" fullword wide
		$r2 = "---BEGIN KEY R_R---" fullword ascii
		$r3 = "!$R4GN4R_" wide
		$r4 = "RAGNRPW" fullword ascii
		$r5 = "---END KEY R_R---" fullword ascii
		$a1 = "+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0" fullword ascii
		$a2 = "\\\\.\\PHYSICALDRIVE%d" fullword wide
		$a3 = "WinSta0\\Default" fullword wide
		$a4 = "%s-%s-%s-%s-%s" fullword wide
		$a5 = "SOFTWARE\\Microsoft\\Cryptography" fullword wide
		$c1 = "-backup" fullword wide
		$c2 = "-force" fullword wide
		$c3 = "-vmback" fullword wide
		$c4 = "-list" fullword wide
		$s1 = ".ragn@r_" wide
		$s2 = "\\notepad.exe" wide
		$s3 = "Opera Software" fullword wide
		$s4 = "Tor browser" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <30KB and (pe.imphash()=="2c2aab89a4cba444cf2729e2ed61ed4f" and ((2 of ($f*)) and (3 of ($r*)) and (4 of ($a*)) and (2 of ($c*)) and (2 of ($s*))))
}