rule SIGNATURE_BASE_APT_NK_MAL_DLL_Apr23_1 : FILE
{
	meta:
		description = "Detects DLLs loaded by shellcode loader (6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad) (relation to Lazarus group)"
		author = "Florian Roth (Nextron Systems)"
		id = "c2abe266-0c21-51aa-9426-46a4f59df937"
		date = "2023-04-03"
		modified = "2023-12-05"
		reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_mal_gopuram_apr23.yar#L43-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e0a8f3896c0119ce399e83fe3e565c66144693e84996aa3d01ca1b6315521782"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "69dd140f45c3fa3aaa64c69f860cd3c74379dec37c46319d7805a29b637d4dbf"
		hash3 = "bb1066c1ca53139dc5a2c1743339f4e6360d6fe4f2f3261d24fc28a12f3e2ab9"
		hash4 = "dca33d6dacac0859ec2f3104485720fe2451e21eb06e676f4860ecc73a41e6f9"
		hash5 = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"

	strings:
		$x1 = "vG2eZ1KOeGd2n5fr" ascii fullword
		$s1 = "Windows %d(%d)-%s" ascii fullword
		$s2 = "auth_timestamp: " ascii fullword
		$s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" wide fullword
		$op1 = { b8 c8 00 00 00 83 fb 01 44 0f 47 e8 41 8b c5 48 8b b4 24 e0 18 00 00 4c 8b a4 24 e8 18 00 00 48 8b 8d a0 17 00 00 48 33 cc }
		$op2 = { 33 d2 46 8d 04 b5 00 00 00 00 66 0f 1f 44 00 00 49 63 c0 41 ff c0 8b 4c 84 70 31 4c 94 40 48 ff c2 }
		$op3 = { 89 5c 24 50 0f 57 c0 c7 44 24 4c 04 00 00 00 c7 44 24 48 40 00 00 00 0f 11 44 24 60 0f 11 44 24 70 0f 11 45 80 0f 11 45 90 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($x*) or 2 of them ) or ($x1 and 1 of ($s*) or 3 of them )
}