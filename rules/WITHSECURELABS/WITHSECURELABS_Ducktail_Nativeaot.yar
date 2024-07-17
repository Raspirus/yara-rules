import "pe"


rule WITHSECURELABS_Ducktail_Nativeaot : FILE
{
	meta:
		description = "Detects NativeAOT variants of DUCKTAIL malware"
		author = "WithSecure"
		id = "1961d3e1-987b-588b-bfc2-8239797cd049"
		date = "2022-11-17"
		modified = "2022-11-22"
		reference = "https://labs.withsecure.com/publications/ducktail_returns"
		source_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/DUCKTAIL/ducktail_nativeaot.yara#L2-L22"
		license_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/LICENSE"
		logic_hash = "976b28ac45e5a13d4ce900b857e6bd3afc82b65b0235791fd698b762287cd60e"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1.0"
		hash1 = "b043e4639f89459cae85161e6fbf73b22470979e"
		hash2 = "073b092bf949c31628ee20f7458067bbb05fda3a"
		hash3 = "d1f6b5f9718a2fe9eaac0c1a627228d3f3b86f87"

	condition:
		uint16(0)==0x5A4D and filesize >15MB and (pe.section_index(".managed")>=0 or pe.exports("DotNetRuntimeDebugHeader")) and pe.exports("SendFile") and pe.exports("Start") and pe.exports("Open")
}