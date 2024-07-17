
rule SIGNATURE_BASE_Oilrig_Myrtille : FILE
{
	meta:
		description = "Detects Oilrig Myrtille RDP Browser"
		author = "Markus Neis"
		id = "e742ab0c-0e21-569e-a100-e5082dc1d372"
		date = "2018-03-22"
		modified = "2022-12-21"
		reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_chafer_mar18.yar#L61-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "373115c0a3fbfe93435aca07cbac52c7649a77d8b7d6eda8af5ce4a1a42e53a6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"

	strings:
		$x1 = "\\obj\\Release\\Myrtille.Services.pdb" ascii
		$x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
		$x3 = "Started rdp client process, remote session {0}" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <50KB and 1 of them
}