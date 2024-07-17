rule SIGNATURE_BASE_MAL_RANSOM_SH_Esxi_Attacks_Feb23_2 : FILE
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		id = "d1282dee-0496-52f1-a2b7-27657ab4df8c"
		date = "2023-02-06"
		modified = "2023-12-05"
		reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_esxi_attacks_feb23.yar#L89-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3f240784873a0239cbf61f7f420fdd72b8992d5943ffc3d4dcad43c836569f4d"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "echo \"START ENCRYPT: $file_e SIZE: $size_kb STEP SIZE: " ascii

	condition:
		filesize <10KB and 1 of them
}