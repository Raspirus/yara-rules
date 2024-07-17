rule TRELLIX_ARC_Vpnfilter : BACKDOOR FILE
{
	meta:
		description = "Filter for 2nd stage malware used in VPNfilter attack"
		author = "Christiaan Beek @ McAfee Advanced Threat Research"
		id = "89bd7f94-d73c-5c5c-a3ec-0331f79e61fd"
		date = "2018-05-23"
		modified = "2020-08-14"
		reference = "https://blog.talosintelligence.com/2018/05/VPNFilter.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_VPNfilter.yar#L1-L40"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "9eb6c779dbad1b717caa462d8e040852759436ed79cc2172692339bc62432387"
		logic_hash = "88f08765dff632f0c08e985181309e5c3ac9cdaa51d05d8485c411fb1a183cca"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/VPNfilter"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "id-at-postalAddress" fullword ascii
		$s2 = "/bin/shell" fullword ascii
		$s3 = "/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB" fullword ascii
		$s4 = "Usage does not match the keyUsage extension" fullword ascii
		$s5 = "id-at-postalCode" fullword ascii
		$s6 = "vTeY4KZMaUrveEel5tWZC94RSMKgxR6cyE1nBXyTQnDOGbfpNNgBKxyKbINWoOJU" fullword ascii
		$s7 = "id-ce-extKeyUsage" fullword ascii
		$s8 = "/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV" fullword ascii
		$s9 = "/etc/config/hosts" fullword ascii
		$s10 = "%s%-18s: %d bits" fullword ascii
		$s11 = "id-ce-keyUsage" fullword ascii
		$s12 = "Machine is not on the network" fullword ascii
		$s13 = "No XENIX semaphores available" fullword ascii
		$s14 = "No CSI structure available" fullword ascii
		$s15 = "Name not unique on network" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <500KB and (8 of them )) or ( all of them )
}