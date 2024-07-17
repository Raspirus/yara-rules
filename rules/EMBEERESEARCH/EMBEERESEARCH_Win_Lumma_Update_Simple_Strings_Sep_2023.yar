
rule EMBEERESEARCH_Win_Lumma_Update_Simple_Strings_Sep_2023 : FILE
{
	meta:
		description = ""
		author = "Matthew @ Embee_Research"
		id = "90209fc6-fd50-5b55-a400-112b2f207885"
		date = "2023-09-13"
		modified = "2023-09-21"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_lumma_updated_sep_2023.yar#L1-L25"
		license_url = "N/A"
		hash = "898a2bdbbb33ccd63b038c67d217554a668a52e9642874bd0f57e08153e6e5be"
		logic_hash = "61571057a5a9c114b6ed5b94b922f2b389406a05e705b3e9e6ddbee221f74c92"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Do you want to run a malware ?" wide
		$s2 = "c2sock" wide
		$s3 = "TeslaBrowser/5" wide
		$s4 = "Crypt build to disable this message" wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ( all of ($s*))
}