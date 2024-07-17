
rule MALPEDIA_Win_Laziok_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1dcbce9e-9b01-55fc-82f2-025bf107fa98"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.laziok"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.laziok_auto.yar#L1-L101"
		license_url = "N/A"
		logic_hash = "8a49fb3e99a85f8254a739f5aaca9e9bb1b5be0f2dd72574e619043b4fccb1ed"
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
		$sequence_0 = { 85f6 740b 837c240cff 8937 7502 }
		$sequence_1 = { 47 68???????? 57 e8???????? 8bf0 59 }
		$sequence_2 = { 8d85f4fdffff 50 e8???????? 33c0 668945fc }
		$sequence_3 = { 68ffffff1f 52 e8???????? 83c410 c3 }
		$sequence_4 = { e8???????? 83c420 5b c20400 }
		$sequence_5 = { 56 8b7508 833e01 7513 6a00 ff7510 ff750c }
		$sequence_6 = { 39742410 741b ff742410 ff15???????? 8bf0 }
		$sequence_7 = { 56 57 ff74240c 33f6 ff35???????? e8???????? }

	condition:
		7 of them and filesize <688128
}