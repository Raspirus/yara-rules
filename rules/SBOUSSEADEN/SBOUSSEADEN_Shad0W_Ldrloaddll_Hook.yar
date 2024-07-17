
rule SBOUSSEADEN_Shad0W_Ldrloaddll_Hook : FILE
{
	meta:
		description = "Shad0w beacon LdrLoadDll hook"
		author = "SBousseaden"
		id = "f9f75b96-2341-553f-b6ca-28d6cb9b880a"
		date = "2020-06-06"
		modified = "2020-06-07"
		reference = "https://github.com/bats3c/shad0w"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/shad0w_ldrhook.yara#L1-L13"
		license_url = "N/A"
		logic_hash = "28e8ca9eee2377fd816dd3bd29e05f4146cea975e0ba5ec180073e10a49895e0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "LdrLoadD"
		$s2 = "SetPr"
		$s3 = "Policy"
		$s4 = {B8 49 BB DE AD C0}

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}