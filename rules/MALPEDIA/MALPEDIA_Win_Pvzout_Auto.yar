rule MALPEDIA_Win_Pvzout_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bc80d9fe-85e4-55f8-8d8b-08382557b556"
		date = "2023-01-25"
		modified = "2023-01-26"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pvzout"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pvzout_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "3b1eb492455f147bf0fe300cd3d173313439f65c62c0ebecede0fab8aacab139"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20230124"
		malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
		malpedia_version = "20230125"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 3e3f 19e9 73f8 dca10ebd24e8 252b0026cb }
		$sequence_1 = { 5a bf95f6810e 75a8 43 1dea50873a d4a1 }
		$sequence_2 = { 9c b3d7 5a bf95f6810e 75a8 }
		$sequence_3 = { bbedffffff 03dd 81eb00d00200 83bd8804000000 899d88040000 }
		$sequence_4 = { 3089f33d80f3 48 e21c 3e3f }
		$sequence_5 = { 5d bbedffffff 03dd 81eb00d00200 83bd8804000000 }
		$sequence_6 = { 03dd 81eb00d00200 83bd8804000000 899d88040000 }
		$sequence_7 = { d4a1 0e 75a8 43 }
		$sequence_8 = { 81eb00d00200 83bd8804000000 899d88040000 0f85cb030000 8d8594040000 50 }
		$sequence_9 = { 5a bf95f6810e 75a8 43 1dea50873a d4a1 0e }

	condition:
		7 of them and filesize <573440
}