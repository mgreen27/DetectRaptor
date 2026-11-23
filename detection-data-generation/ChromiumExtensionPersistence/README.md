# Chromium extension persistence lab

Generate inert Chrome or Edge extension registrations and a native messaging host for [ChromiumExtensionPersistence](../../vql/ChromiumExtensionPersistence.yaml). Use a disposable Windows VM and run the scripts as the test user in Windows PowerShell 5.1 or PowerShell 7. The extension service workers only log a lab message. The native host manifest points to a deliberately missing executable.

## Generate and collect

Close Chrome and Edge, including background processes. From this folder, run:

```powershell
.\Install-ChromiumExtensionLab.ps1 -Browser Chrome -ProfileName DetectRaptorLab -SyntheticProfile
```

This creates or updates the named profile. Use `-Browser Both` to exercise Edge too. The installer records generated IDs, estimated scores, state, and preference backups under `%LOCALAPPDATA%\DetectRaptorLabState`. Use `Get-Help .\Install-ChromiumExtensionLab.ps1 -Detailed` for case selection and path overrides.

Before restarting the browser, collect both sources of the artifact on the VM. Chromium may discard synthetic entries on startup. In the Extensions source, check these cases:

| Case | Expected observation |
|---|---|
| A | Unpacked Google Chrome with debugger permission and a masquerading name, HIGH |
| B | Localized name resolves to Chrome Update, HIGH |
| C | Off-store internal extension named Microsoft Edge |
| D | Debugger permission on Page Timing |
| E | Ordinary unpacked developer extension |
| F | Command-line Chrome Helper with native messaging permission |
| G | Unpacked Tab Sync with a managed copy |
| H | Web Store control below the default threshold. Collect with ShowAll enabled to see it. |

The reviewed Chrome export returned A at 180 and B at 170. These are observations from one profile. An unpacked entry gets five extra points when the encrypted settings hash is absent. The installer models enabled entries with empty disable_reasons by default. Its legacy state option writes state=1.

In NativeMessagingHosts, check that com.detectraptor.lab.host allows the generated case F ID and reports a missing executable. One Windows collection scored this host at 65. A later collection returned zero rows even though the registration had been observed in live HKCU. If N is missing, compare live HKCU with results from Windows.Registry.NTUser for the same SID and collection time.

## Remove

Close both browsers and run as the same test user:

```powershell
.\Uninstall-ChromiumExtensionLab.ps1
```

Collect again and check that the generated IDs, lab paths, and host registration have disappeared. The uninstaller uses its recorded state and markers. It restores backed-up preferences when the installed file is unchanged and preserves intervening changes during normal cleanup.

## Source and license

Adapted from [DetectRaptor-ChromiumExtensionLab at 1989756](https://github.com/mgreen27/DetectRaptor-ChromiumExtensionLab/tree/19897566726af4c12adc375bb78697aa8fb0eece).

MIT License

Copyright (c) 2026 Matt Green

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
