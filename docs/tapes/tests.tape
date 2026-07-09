# AutoTriage — quality gate (49 tests). Render: vhs docs/tapes/tests.tape
Output docs/media/tests.gif
Require python
Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 820
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 45ms
Set Framerate 24

Hide
Type "cd /Users/rohan/Razorpay/autotriage && source .venv/bin/activate && clear"
Enter
Show
Sleep 600ms
Type "pytest -q"
Sleep 400ms
Enter
Sleep 6s
