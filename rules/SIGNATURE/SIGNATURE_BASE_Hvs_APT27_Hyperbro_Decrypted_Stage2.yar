import "pe"


import "pe"


rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Decrypted_Stage2 : FILE
{
	meta:
		description = "HyperBro Stage 2 and compressed Stage 3 detection"
		author = "Moritz Oettle"
		id = "039e5d41-eadb-5c53-82cd-20ffd4105326"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt27_hyperbro.yar#L35-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6eb56c4a92e89977e536ccc3c70170062aca072c6981b40aeea184ea2ca461a6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "fc5a58bf0fce9cb96f35ee76842ff17816fe302e3164bc7c6a5ef46f6eff67ed"

	strings:
		$lznt1_compressed_pe_header_small = { FC B9 00 4D 5A 90 }
		$lznt1_compressed_pe_header_large_1 = { FC B9 00 4D 5A 90 00 03 00 00 00 82 04 00 30 FF FF 00 }
		$lznt1_compressed_pe_header_large_2 = { 00 b8 00 38 0d 01 00 40 04 38 19 00 10 01 00 00 }
		$lznt1_compressed_pe_header_large_3 = { 00 0e 1f ba 0e 00 b4 09 cd 00 21 b8 01 4c cd 21 }
		$lznt1_compressed_pe_header_large_4 = { 54 68 00 69 73 20 70 72 6f 67 72 00 61 6d 20 63 }
		$lznt1_compressed_pe_header_large_5 = { 61 6e 6e 6f 00 74 20 62 65 20 72 75 6e 00 20 69 }
		$lznt1_compressed_pe_header_large_6 = { 6e 20 44 4f 53 20 00 6d 6f 64 65 2e 0d 0d 0a 02 }

	condition:
		filesize <200KB and ($lznt1_compressed_pe_header_small at 0x9ce) or ( all of ($lznt1_compressed_pe_header_large_*))
}