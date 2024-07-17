import "pe"


import "pe"


rule SIGNATURE_BASE_APT_MAL_Gopuram_Backdoor_Apr23 : FILE
{
	meta:
		description = "Detects Gopuram backdoor"
		author = "X__Junior (Nextron Systems)"
		id = "3ae5ddcb-5601-5dca-85dd-0a4772577fae"
		date = "2023-02-24"
		modified = "2023-12-05"
		reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_mal_gopuram_apr23.yar#L20-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aa3dd1f35d27d23eb775410cceae81d5b767dc0f1636aac67f2d2e988a3ed995"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "beb775af5196f30e0ee021790a4978ca7a7ac2a7cf970a5a620ffeb89cc60b2c"
		hash2 = "97b95b4a5461f950e712b82783930cb2a152ec0288c00a977983ca7788342df7"

	strings:
		$x1 = "%s\\config\\TxR\\%s.TxR.0.regtrans-m" ascii
		$xop = { D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE D1 E8 33 C3 D1 EB A8 01 74 ?? 81 F3 25 A3 87 DE }
		$opa1 = { 48 89 44 24 ?? 45 33 C9 45 33 C0 33 D2 89 5C 24 ?? 48 89 74 24 ?? 48 89 5C 24 ?? 89 7C 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 4C 24 ?? 44 8D 43 }
		$opa2 = { 48 89 B4 24 ?? ?? ?? ?? 44 8D 43 ?? 33 D2 48 89 BC 24 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 45 33 C0 33 D2 8B F8 E8 ?? ?? ?? ?? 8D 4F ?? E8 ?? ?? ?? ?? 4C 8B 4C 24 ?? 44 8D 43 ?? 48 8B C8 8B D7 48 8B F0 44 8B F7 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? E8  }

	condition:
		( uint16(0)==0x5A4D and filesize <2MB and pe.characteristics&pe.DLL and 1 of ($x*)) or all of ($opa*)
}