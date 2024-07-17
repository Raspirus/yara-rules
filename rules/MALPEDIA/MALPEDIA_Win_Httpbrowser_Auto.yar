
rule MALPEDIA_Win_Httpbrowser_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "86ed1f1e-9c83-5189-8446-3be88e9701cf"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpbrowser"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.httpbrowser_auto.yar#L1-L178"
		license_url = "N/A"
		logic_hash = "5b5149262889d64634c3067408a546cd5b0c2e08f2004303b6cf9132eb7eeb82"
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
		$sequence_0 = { 50 ff7508 6a00 53 ffd6 8b45fc 33c9 }
		$sequence_1 = { 50 895de0 ff5604 8945f0 85db 0f8489010000 }
		$sequence_2 = { 33c5 8945fc 53 56 57 8d859cfeffff 33ff }
		$sequence_3 = { 8d85f0fdffff 50 8d85d0f5ffff 50 ff15???????? }
		$sequence_4 = { 56 6a03 6800000040 8d85f4fdffff 50 ff15???????? }
		$sequence_5 = { e8???????? 83c40c 33c0 56 668985c8f3ffff 8d85caf3ffff }
		$sequence_6 = { 83c438 ff15???????? 8d85f4fdffff 50 53 57 }
		$sequence_7 = { ffb5f4edffff 8d85fcfdffff ffb5f8edffff 68???????? 50 }
		$sequence_8 = { e8???????? 68c20ddf13 56 a3???????? e8???????? 83c438 }
		$sequence_9 = { 6a00 6810040000 ff15???????? 8bf0 57 6a0e 56 }
		$sequence_10 = { 83c414 c745ec00000000 68???????? 50 9c b80a000000 51 }
		$sequence_11 = { b905000000 8db524ffffff 8dbda4feffff 8945e4 }
		$sequence_12 = { 33c0 8dbd26ffffff 66899524ffffff f3ab 8955e8 8955f8 8955fc }
		$sequence_13 = { 40 0068ae 224000 50 b822010000 }
		$sequence_14 = { 8895a0c5ffff f3ab aa b91f000000 33c0 8dbd4affffff 66899548ffffff }
		$sequence_15 = { 8b15???????? 8945d8 a1???????? 894ddc 668b0d???????? }

	condition:
		7 of them and filesize <188416
}