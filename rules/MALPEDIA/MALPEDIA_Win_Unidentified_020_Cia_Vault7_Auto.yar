
rule MALPEDIA_Win_Unidentified_020_Cia_Vault7_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "229fefe8-12a2-5321-841b-a1c5858ad20f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_020_cia_vault7"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_020_cia_vault7_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "121c8e165e7a80ef0b3dea83e1137d20669defc5a0d83275fbb5b7562347ae72"
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
		$sequence_0 = { 6a08 6a01 52 ff15???????? 85c0 0f859f000000 8b45d0 }
		$sequence_1 = { 57 ff15???????? 8bf0 85f6 0f8470ffffff 8b85ecfdffff }
		$sequence_2 = { 6a00 6a00 6a00 6a00 8d95f4fdffff 52 6a01 }
		$sequence_3 = { 8bc1 c1f805 8bf1 83e61f 8d3c8520834100 8b07 }
		$sequence_4 = { 0f870d0a0000 ff2485bbce4000 33c0 838df4fbffffff 898598fbffff 8985b0fbffff }
		$sequence_5 = { 33d2 6806020000 52 8d85eafbffff 50 668995e8fbffff e8???????? }
		$sequence_6 = { 5d c3 b984120000 b8???????? }
		$sequence_7 = { 8d45f4 50 52 51 57 ff15???????? 8b4d08 }
		$sequence_8 = { 50 51 ff15???????? 85c0 7420 8b55fc }
		$sequence_9 = { 83ffff 7410 8d4c2420 51 }

	condition:
		7 of them and filesize <253952
}