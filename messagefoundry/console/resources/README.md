# Console icon resources

- **`app.ico`** — the MessageFoundry badge (multi-resolution: 16/24/32/48/64/128/256 px). Used for
  the console window title bar + Windows taskbar (set in
  [`../__main__.py`](../__main__.py) via `_app_icon()`) and for the Desktop / Start-Menu shortcut
  ([`scripts/console/install-console-shortcut.ps1`](../../../scripts/console/install-console-shortcut.ps1)).
  It ships in the wheel automatically (hatchling packages everything under `messagefoundry/`).
- **`app.svg`** — the vector source (the project website's badge logo, itself derived from the
  VS Code extension's [`ide/media/icon.svg`](../../../ide/media/icon.svg)).

## Regenerating `app.ico` from `app.svg`

Needs **Inkscape** to rasterize (no Python imaging dependency). Render the PNG frames, then pack them
with the stdlib packer:

```powershell
$ink = "C:\Program Files\Inkscape\bin\inkscape.com"
foreach ($s in 16,24,32,48,64,128,256) {
    & $ink app.svg --export-type=png --export-filename="frame-$s.png" --export-area-page -w $s -h $s
}
python ..\..\..\scripts\console\pack_ico.py .   # writes app.ico from the frame-*.png files
Remove-Item frame-*.png
```
