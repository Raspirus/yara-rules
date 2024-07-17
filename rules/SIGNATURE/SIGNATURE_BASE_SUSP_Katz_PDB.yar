rule SIGNATURE_BASE_SUSP_Katz_PDB : FILE
{
	meta:
		description = "Detects suspicious PDB in file"
		author = "Florian Roth (Nextron Systems)"
		id = "79f4f07c-b234-5203-a2ab-aba4a9cb9f8d"
		date = "2019-02-04"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4619-L4632"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1a38f63d8e8baa9bc8f34c1886fc2aaea7f61d5e09792ba9cde4cf6ed8441fab"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"

	strings:
		$s1 = /\\Release\\[a-z]{0,8}katz.pdb/
		$s2 = /\\Debug\\[a-z]{0,8}katz.pdb/

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and all of them
}