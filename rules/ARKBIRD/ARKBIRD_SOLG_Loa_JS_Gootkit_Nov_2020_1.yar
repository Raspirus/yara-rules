
rule ARKBIRD_SOLG_Loa_JS_Gootkit_Nov_2020_1 : FILE
{
	meta:
		description = "Detect JS loader used on the Gootkit killchain (November 2020)"
		author = "Arkbird_SOLG"
		id = "649133bd-a44c-5d99-befa-0508fed27ed8"
		date = "2020-11-21"
		modified = "2020-11-21"
		reference = "https://twitter.com/ffforward/status/1330214661577437187"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-21/Gootkit/Loa_JS_Gootkit_Nov_2020_1.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "f24d31e7107b8c59b969481596a5e1369933bf2b0fa5117cd1aa5f7ea116d8d5"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "7aec3ed791529182c0f64ce34415c3c705a79f3d628cbcff70c34a9f73d8ff42"

	strings:
		$s1 = { 7b [4-6] 5b [4-6] 5d 28 [4-6] 5b [4-6] 5d 29 28 [4-6] 5b [4-6] 5d 29 3b 7d }
		$s2 = { 7b 72 65 74 75 72 6e 20 [4-6] 20 25 20 28 [4-6] 2b [4-6] 29 3b 7d }
		$s3 = { 7b [4-6] 20 3d 20 [4-6] 28 [4-6] 29 2e 73 70 6c 69 74 28 [4-6] 29 3b 7d }
		$s4 = { 7b 72 65 74 75 72 6e 20 [4-6] 2e 63 68 61 72 41 74 28 [4-6] 29 3b 7d}
		$s5 = { 7b [4-6] 5b [4-6] 5d 20 3d 20 [4-6] 5b [4-6] 5b [4-6] 5d 5d 3b 7d }

	condition:
		filesize >1KB and 2 of them
}