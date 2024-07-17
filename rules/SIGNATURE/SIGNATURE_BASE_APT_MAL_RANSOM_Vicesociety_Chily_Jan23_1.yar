
rule SIGNATURE_BASE_APT_MAL_RANSOM_Vicesociety_Chily_Jan23_1 : FILE
{
	meta:
		description = "Detects Chily or SunnyDay malware used by Vice Society"
		author = "Florian Roth (Nextron Systems)"
		id = "1be4adb9-e60c-5023-9230-07f5fd16daaa"
		date = "2023-01-12"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ransom_vicesociety_dec22.yar#L33-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fc2967d86bf73033e68b8b9409a197ae8f7fcdf06e1e2a17e3d277d243caa541"
		score = 80
		quality = 83
		tags = "FILE"
		hash1 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"

	strings:
		$x1 = ".[Chily@Dr.Com]" ascii fullword
		$s1 = "localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a>" ascii fullword
		$s2 = "C:\\Users\\root\\Desktop" ascii fullword
		$s3 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" wide fullword
		$s4 = "cd %userprofile%\\documents\\" wide
		$s5 = "noise.bmp" wide fullword
		$s6 = " Execution time: %fms (1sec=1000ms)" ascii fullword
		$s7 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide fullword
		$op1 = { 4c 89 c5 89 ce 89 0d f5 41 02 00 4c 89 cf 44 8d 04 49 0f af f2 89 15 e9 41 02 00 44 89 c0 }
		$op2 = { 48 8b 03 48 89 d9 ff 50 10 84 c0 0f 94 c0 01 c0 48 83 c4 20 5b }
		$op3 = { 31 c0 47 8d 2c 00 45 85 f6 4d 63 ed 0f 8e ec 00 00 00 0f 1f 80 00 00 00 00 0f b7 94 44 40 0c 00 00 83 c1 01 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($x*) or 3 of them ) or 4 of them
}