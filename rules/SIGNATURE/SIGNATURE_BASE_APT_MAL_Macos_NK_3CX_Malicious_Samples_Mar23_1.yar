import "pe"


rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_Malicious_Samples_Mar23_1 : FILE
{
	meta:
		description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		id = "ff39e577-7063-5025-bead-68394a86c87c"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L168-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c2733c2f7dcca82e5a0b2301777fb54853d04dfa893bcf88ecbec34d37e1a38a"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
		hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
		hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"

	strings:
		$s1 = "20230313064152Z0"
		$s2 = "Developer ID Application: 3CX (33CF4654HL)"

	condition:
		( uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca) and all of them
}