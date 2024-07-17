rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_2 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "d5c3d530-ed6f-563e-a3b0-55d4c82e4899"
		date = "2022-05-07"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L78-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7525c675dbba6eb480f1d28fc6db05bd9907725c291e64ee6dc2453fd42892a0"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"

	strings:
		$opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
		$opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }
		$op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
		$op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
		$op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }

	condition:
		uint16(0)==0x457f and filesize <100KB and 2 of ($opx*) or 4 of them
}