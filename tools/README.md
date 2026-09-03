# tools

`snui.py` – the harness every story build/test/export script in this repo uses.
It logs in to the PDI as the working user, runs background scripts (global or
scoped), switches the session application, exports update sets the way the
platform's own *Export to XML* does, and can push an exported file through the
UI import path to prove it loads with all its updates.

```
export SN_USER=<working user id>
export SN_PASSWORD=<password>          # never commit it
python3 tools/snui.py < script.js      # run a background script in global
```

Scripts under `stories/*/` import it with
`sys.path.insert(0, '<repo>/tools'); from snui import SNUI` and call `SNUI()`.
