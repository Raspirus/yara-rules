rule MALPEDIA_Win_Ddkong_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0544faa5-2134-56f3-b2ce-99d63d7f2f59"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ddkong"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ddkong_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "5c0b95ff5255c02a1d1a9b0883f78a353561d54588ac72196452124efb25472a"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { c6459765 c6459857 c645996f c6459a77 c6459b36 c6459c34 c6459d46 }
		$sequence_1 = { c68572ffffff62 c68573ffffff6a c68574ffffff65 c68575ffffff63 c68576ffffff74 889d77ffffff ffd7 }
		$sequence_2 = { c645d36c c645d465 c645d54e c645d661 c645d76d c645d865 c645d941 }
		$sequence_3 = { 5b 5d c20c00 ff25???????? ff25???????? 8b4c2404 85c9 }
		$sequence_4 = { c645f470 ffd6 50 ffd7 8b5d0c bf04010000 }
		$sequence_5 = { 6a04 e8???????? 83c418 eb2d 6a01 }
		$sequence_6 = { 7427 837d08ff 7421 8d45dc 6a10 50 ff7508 }
		$sequence_7 = { c6855affffff65 c6855bffffff4f c6855cffffff62 c6855dffffff6a c6855effffff65 }
		$sequence_8 = { c6459763 c6459874 c6459969 c6459a76 c6459b65 c6459c43 c6459d6f }
		$sequence_9 = { c68574ffffff65 c68575ffffff63 c68576ffffff74 889d77ffffff }

	condition:
		7 of them and filesize <81920
}