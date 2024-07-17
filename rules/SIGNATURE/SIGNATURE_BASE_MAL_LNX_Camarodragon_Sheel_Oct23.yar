
rule SIGNATURE_BASE_MAL_LNX_Camarodragon_Sheel_Oct23 : FILE
{
	meta:
		description = "Detects CamaroDragon's tool named sheel"
		author = "Florian Roth"
		id = "f6f08c0e-236c-5194-9369-da8fdef4aa21"
		date = "2023-10-06"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_camaro_dragon_oct23.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b06f645b766a099adb71c144bdced70c130735e75d5be6451f71077c7d3a5d19"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"

	strings:
		$x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
		$s1 = "read_ip" ascii fullword
		$s2 = "open fail.%m" ascii fullword
		$s3 = "ri:h:p:" ascii fullword
		$s4 = "update server list success!" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <30KB and (1 of ($x*) or 3 of them ) or 4 of them
}