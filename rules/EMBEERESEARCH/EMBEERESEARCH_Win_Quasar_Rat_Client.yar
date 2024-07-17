rule EMBEERESEARCH_Win_Quasar_Rat_Client : FILE
{
	meta:
		description = "Detects strings present in Quasar Rat Samples."
		author = "Matthew @ Embee_Research"
		id = "7fc0bd6d-e187-51b7-a8b8-68b17271cef8"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_quasar_rat_client_aug_2023.yar#L3-L37"
		license_url = "N/A"
		hash = "914d88f295ac2213f37d3f71e6d4383979283d1728079a208f286effb44d840c"
		hash = "45a724179ae1d08044c4bafb69c7f9cdb4ed35891dc9cf24aa664d75464ceb6d"
		hash = "7e13bcd73232c3f33410aa95f61e1196a2f9ae35e05c1f9c8f251e07077a9dfb"
		logic_hash = "efba911780ffb144f277e88ff8ca8f53a90c32a677ccb19ec26e71f974a1b91f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Quasar Client" ascii wide
		$s2 = "Quasar.Client.Properties.Resources" ascii wide
		$s3 = "Google\\Chrome\\User Data\\Default\\" wide
		$s4 = "\\Mozilla\\Firefox\\Profiles" wide
		$s5 = "Yandex\\YandexBrowser\\User Data\\Default\\" wide

	condition:
		uint16(0)==0x5a4d and dotnet.is_dotnet and filesize <7000KB and ( for any i in (0..dotnet.number_of_resources-1) : (dotnet.resources[i].name=="Quasar.Client*") or (3 of ($s*)))
}