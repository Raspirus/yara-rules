rule HARFANGLAB_Donut_Shellcode : FILE
{
	meta:
		description = "Detects Donut shellcode in memory."
		author = "HarfangLab"
		id = "54facb12-3f33-5430-b4bf-0d223dc2a413"
		date = "2024-06-20"
		modified = "2024-06-28"
		reference = "TRR240601"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240601/trr240601_yara.yar#L18-L66"
		license_url = "N/A"
		logic_hash = "1bf4e253195e39cc0b3cf45797c35a9f06078350aa35e65d9d36adbcc09a150b"
		score = 75
		quality = 80
		tags = "FILE"
		context = "memory"

	strings:
		$amsi_patch = { 48 8B 44 24 (28 | 30) 83 20 00 33 C0 C3 }
		$wldp_patch = { 41 C7 00 01 00 00 00 33 C0 C3 }
		$api_hashing = { 8B C2 C1 C9 08 41 03 C8 8B D3 41 33 C9 C1 CA 08 41 03 D1 41 C1 C0 03 41 33 D2 41 C1 C1 03 44 33 CA 44 33 C1 41 FF C2 41 8B DB 44 8B D8 41 83 FA 1B }
		$loaded_dlls = "ole32;oleaut32;wininet;mscoree;shell32" ascii
		$function_1 = "WldpQueryDynamicCodeTrust" ascii
		$function_2 = "WldpIsClassInApprovedList" ascii
		$function_3 = "AmsiInitialize" ascii
		$function_4 = "AmsiScanBuffer" ascii
		$function_5 = "AmsiScanString" ascii

	condition:
		uint8(0)==0xE8 and ((#amsi_patch>1 and $wldp_patch and $api_hashing) or ($loaded_dlls and all of ($function_*)))
}