# DetectRaptor
A repository to share publicly available bulk Velociraptor detection content in an easy to consume way.

Simply take the release [VQL zip](https://github.com/mgreen27/DetectRaptor/releases/download/DetectRaptor/DetectRaptorVQL.zip)
and import it into Velociraptor.  

This is made easy via the Velociraptor artifact exchange: [Server.Import.DetectRaptor](https://docs.velociraptor.app/exchange/artifacts/pages/detectraptor/)
1. Import Velociraptor Artifact Exchange
   Server Artifacts > + Server.Import.ArtifactExchange
![image](https://github.com/user-attachments/assets/b826c858-5e55-4896-a382-d58f2c7d8b96)

This should import the "Import DetectRaptor" artifact.

2. Import DetectRaptor
   Server Artifacts > + Exchange.Server.Import.DetectRaptor
![image](https://github.com/user-attachments/assets/d75ade94-455d-40a1-94be-ea45b8e0fa30)




Current artifacts include:
- Windows.Detection.Amcache
- Windows.Detection.Applications
- Windows.Detection.BinaryRename
- Windows.Detection.Bootloaders
- Windows.Detection.Evtx
- Windows.Detection.HijackLibsEnv
- Windows.Detection.HijackLibsMFT
- Windows.Detection.LolDriversMalicious
- Windows.Detection.LolDriversVulnerable
- Windows.Detection.LolRMM
- Windows.Detection.MFT
- Windows.Detection.NamedPipes
- Windows.Detection.Powershell.ISEAutoSave
- Windows.Detection.Powershell.PSReadline
- Windows.Detection.Webhistory
- Windows.Detection.ZoneIdentifier
- Generic.Detection.WebshellYara
- Linux.Detection.YaraProcessLinux
- Windows.Detection.YaraProcessWin
- Macos.Detection.YaraProcessMacos
- Server.StartHunts

Some contributing repositories:
- https://github.com/svch0stz/velociraptor-detections
- https://www.bootloaders.io/
- https://hijacklibs.net/
- https://www.loldrivers.io/
- https://www.lolrmm.io/
- https://github.com/SigmaHQ/sigma
- https://yarahq.github.io/
