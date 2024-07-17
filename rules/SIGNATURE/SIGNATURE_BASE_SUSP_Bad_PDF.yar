
rule SIGNATURE_BASE_SUSP_Bad_PDF : FILE
{
	meta:
		description = "Detects PDF that embeds code to steal NTLM hashes"
		author = "Florian Roth (Nextron Systems), Markus Neis"
		id = "149cf20c-4cfd-5b07-acc5-06ae25b209b1"
		date = "2018-05-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_bad_pdf.yar#L1-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "59b159aaccf5c3b64fee17831c1e3a1ca99b60dbb725ad25a4ddad47cdc442d7"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "d8c502da8a2b8d1c67cb5d61428f273e989424f319cfe805541304bdb7b921a8"

	strings:
		$s1 = "         /F (http//" ascii
		$s2 = "        /F (\\\\\\\\" ascii
		$s3 = "<</F (\\\\" ascii

	condition:
		( uint32(0)==0x46445025 or uint32(0)==0x4450250a) and 1 of them
}