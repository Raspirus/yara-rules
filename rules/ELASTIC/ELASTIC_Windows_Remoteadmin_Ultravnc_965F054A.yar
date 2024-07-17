rule ELASTIC_Windows_Remoteadmin_Ultravnc_965F054A : FILE MEMORY
{
	meta:
		description = "Detects Windows Remoteadmin Ultravnc (Windows.RemoteAdmin.UltraVNC)"
		author = "Elastic Security"
		id = "965f054a-4b78-43f3-87db-1ecd64c317a0"
		date = "2023-03-18"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_RemoteAdmin_UltraVNC.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "59bddb5ccdc1c37c838c8a3d96a865a28c75b5807415fd931eaff0af931d1820"
		logic_hash = "a9b9d0958f09b23fa7b27ef7ec32b3feb98edca3be5a21552a3a2f50e3fd41c1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7e612ffb9fdf94471f938039b4077d5546edd5d6f700733e1c1e732aef36ed42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = ".\\vncsockconnect.cpp"
		$s2 = ".\\vnchttpconnect.cpp"
		$s3 = ".\\vncdesktopthread.cpp"
		$s4 = "Software\\UltraVNC"
		$s5 = "VncCanvas.class"
		$s6 = "WinVNC_Win32_Instance_Mutex"
		$s7 = "WinVNC.AddClient"

	condition:
		5 of them
}