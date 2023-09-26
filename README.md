# DetectRaptor
A repository to share publicly available bulk Velociraptor detection content in an easy to consume way.

Simply take the release [VQL zip](https://github.com/mgreen27/DetectRaptor/releases/download/DetectRaptor/DetectRaptorVQL.zip)
and import it into Velociraptor.  

This is made easy via the Velociraptor artifact exchange: [Server.Import.DetectRaptor](https://docs.velociraptor.app/exchange/artifacts/pages/detectraptor/)

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
- Windows.Detection.MFT
- Windows.Detection.NamedPipes
- Windows.Detection.Powershell.ISEAutoSave
- Windows.Detection.Powershell.PSReadline
- Windows.Detection.Webhistory
- Windows.Detection.ZoneIdentifier
- Server.StartHunts

Some contributing repositories:
- https://github.com/svch0stz/velociraptor-detections
- https://www.bootloaders.io/
- https://hijacklibs.net/
- https://www.loldrivers.io/
- https://github.com/SigmaHQ/sigma
