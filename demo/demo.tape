# vhs tape — renders the README demo gif.
# Run from the repo root:  vhs demo/demo.tape
Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1320
Set Height 840
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Sleep 600ms
Type ".venv/bin/python demo/demo.py"
Enter
Sleep 15s
Sleep 1500ms
