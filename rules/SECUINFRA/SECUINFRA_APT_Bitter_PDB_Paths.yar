rule SECUINFRA_APT_Bitter_PDB_Paths : FILE
{
	meta:
		description = "Detects Bitter (T-APT-17) PDB Paths"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "e2ad4ac3-45fe-5087-b0d6-a5de16774229"
		date = "2022-06-22"
		modified = "2022-07-05"
		reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L110-L133"
		license_url = "N/A"
		logic_hash = "7eb9e4c1b4e0cca070596f3702045756eb32716481bb59f2f8322221804291f5"
		score = 75
		quality = 70
		tags = "FILE"
		tlp = "WHITE"
		hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

	strings:
		$pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
		$pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"
		$pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
		$pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

	condition:
		uint16(0)==0x5a4d and any of ($pdbPath*)
}