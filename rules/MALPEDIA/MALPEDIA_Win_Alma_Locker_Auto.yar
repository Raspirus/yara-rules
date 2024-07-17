
rule MALPEDIA_Win_Alma_Locker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a8975e90-f59f-53dc-8c8c-bbe753edcfd3"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_locker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.alma_locker_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "df780972bf15a2baf7532cad09aa2dd13a5bee9ccc29d4fb62357c0162af8a26"
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
		$sequence_0 = { 8d8d6cfeffff e8???????? 83c404 8d4d8c c645fc07 51 8bd0 }
		$sequence_1 = { 720e ffb5ccfeffff e8???????? 83c404 837da008 720b ff758c }
		$sequence_2 = { 0304b5e86a0210 59 eb02 8bc3 8a4024 247f 3c01 }
		$sequence_3 = { 50 ff15???????? 8bf0 89b52cfaffff }
		$sequence_4 = { 83e11f c1f805 c1e106 8b0485e86a0210 f644080401 7405 }
		$sequence_5 = { 8d8dd0fbffff e8???????? c645fc03 8d85d0fbffff 83bde4fbffff10 0f4385d0fbffff }
		$sequence_6 = { b9???????? e8???????? 33c0 c645fc1f 33c9 66a3???????? 66390d???????? }
		$sequence_7 = { 81fbfeffff7f 0f87ab000000 8b4614 3bc3 7325 ff7610 53 }
		$sequence_8 = { b9???????? c705????????07000000 0f44f8 c705????????00000000 57 68???????? }
		$sequence_9 = { 83c404 c78584fbffff0f000000 c78580fbffff00000000 c68570fbffff00 83bd9cfbffff10 720e }

	condition:
		7 of them and filesize <335872
}