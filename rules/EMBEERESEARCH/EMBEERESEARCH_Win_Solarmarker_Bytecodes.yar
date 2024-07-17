import "dotnet"


rule EMBEERESEARCH_Win_Solarmarker_Bytecodes : FILE
{
	meta:
		description = "Detects bytecodes present in solarmarker Packer"
		author = "Matthew @ Embee_Research"
		id = "d405e7ae-f09b-5993-a510-e5e1bc289898"
		date = "2023-09-10"
		modified = "2023-09-11"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_solarmarker_bytecodes_aug_2023.yar#L3-L21"
		license_url = "N/A"
		hash = "a433dad1e31f2e19ab5d22b6348c73fa4c874502acc20d5517d785b554754279"
		logic_hash = "52256184706b7173ee8e8683ac79c1b9d4773778c135e4dae255376c0a6651fb"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = {8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 20 ?? ?? ?? ?? 13 ?? 06 11 ?? 20 ?? ?? ?? ?? 58 D1 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 20 ?? ?? ?? ?? 13 ?? 06 11 ?? 20 ?? ?? ?? ?? 58 D1 8C ?? ?? ?? ?? 28 ?? ?? ?? ??}

	condition:
		dotnet.is_dotnet and filesize <7000KB and $s1
}