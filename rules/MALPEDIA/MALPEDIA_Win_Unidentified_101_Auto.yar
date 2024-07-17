
rule MALPEDIA_Win_Unidentified_101_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1e5a977c-e7e9-5732-97b6-6aadc4f691fc"
		date = "2023-03-28"
		modified = "2023-04-07"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_101"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_101_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "71f0751fbd77a928634515b558d06922b4bf4a312042d6abbd6ba70171c64843"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20230328"
		malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
		malpedia_version = "20230407"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { c70016000000 e8???????? 83c8ff e9???????? 498bc4 488d0ddb070100 83e03f }
		$sequence_1 = { 6689842404010000 b865000000 6689842406010000 33c0 6689842408010000 }
		$sequence_2 = { 33c0 b968000000 f3aa 488d842400010000 4889442448 488d842430020000 4889442440 }
		$sequence_3 = { 4889742410 57 4883ec20 418bf0 4c8d0debb40000 8bda 4c8d05dab40000 }
		$sequence_4 = { c744243000000000 4c8d4c2430 4c8b442440 8b542468 488b4c2460 }
		$sequence_5 = { c68424e900000065 c68424ea00000057 c68424eb00000000 c644243052 c644243165 c644243261 c644243364 }
		$sequence_6 = { 428a8c1910e40100 4c2bc0 418b40fc 4d894108 d3e8 41894120 }
		$sequence_7 = { 48c744242000000000 4c8d8c24c8000000 448b442450 488b542458 488b4c2470 ff15???????? }
		$sequence_8 = { 41b804010000 488d942400030000 33c9 ff15???????? c744245801000000 e8???????? 833d????????01 }
		$sequence_9 = { 7528 48833d????????00 741e 488d0dd8450100 e8???????? 85c0 740e }

	condition:
		7 of them and filesize <402432
}