# WinDivert 2.2.2 (x64)

Used by usandbox for transparent capture (`--capture transparent`, the default in filter mode).

- Source: https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
  (sha256 of the zip: `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`)
- `WinDivert.dll` sha256 `C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2` (not Authenticode-signed)
- `WinDivert64.sys` sha256 `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2`
  (Authenticode: valid, EV signature of 成都密思听科技有限公司, the signer the upstream release uses)
- License: LGPL-3.0 or GPL-2.0 (see `LICENSE`). usandbox loads the unmodified DLL dynamically.

The build copies both files next to `usandbox.exe`. Without them usandbox falls back to proxy
settings plus the firewall lock.
