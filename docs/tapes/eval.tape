# AutoTriage — offline evaluation (no API key). Render: vhs docs/tapes/eval.tape
Output docs/media/eval.gif
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
Type "# Score the agent against the labeled set — offline stub, no API key"
Enter
Type "python evals/run_eval.py --stub"
Sleep 400ms
Enter
Sleep 5s
