import "dotnet"


import "dotnet"


import "dotnet"


import "dotnet"


rule EMBEERESEARCH_Win_Cobalt_Strike_Loader_Shellcode_Jun_2023 : FILE
{
	meta:
		description = "Detection of an encoder observed with Cobalt Strike shellcode"
		author = "Matthew @ Embee_research"
		id = "ea52b9e7-f2bd-5c9f-9ee1-506baa48be84"
		date = "2023-07-03"
		modified = "2023-07-03"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_cobalt_shellcode_encoder_jun_2023.yar#L1-L21"
		license_url = "N/A"
		logic_hash = "42b4b9ab681f3164168de84e76bcd8161865fa9e5871d70a6de534b23896e4f0"
		score = 75
		quality = 75
		tags = "FILE"
		vendor = ""

	strings:
		$get_enc_offset = {8b 88 c0 00 00 00 8b 90 c4 00 00 00 48 8d b0 c8 00 00 00}
		$decode_loop = {ac 83 e1 03 d2 c8 ff c1 aa ff ca 75 f3}
		$b64_initial_bytes = "SInISIlMJAiLiMAAAACLkMQAAABIjbDIAAAA" wide ascii

	condition:
		(($get_enc_offset and $decode_loop) or $b64_initial_bytes) and filesize <10000KB
}