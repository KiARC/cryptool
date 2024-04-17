# CrypTool

Cryptool is a tool I wrote out of frustration. There aren't a lot of good ways to just encrypt something on the command line. I was writing down a router password in Logseq and thought to myself, "Maybe storing this in plaintext isn't the greatest idea...". After about half an hour of looking for a way to encrypt it I ended up writing my own tool.

Cryptool supports both AES-256-GCM and XChaCha-Poly1305, can encrypt files and strings, and is fully interactive. It is not meant for automation, though I certainly might add one-liner functionality if I ever end up needing it. The point of cryptool is not to be the most efficient solution, but the one with the least friction. If you want to encrypt something, cryptool will do it.

Cryptool is powered by [Huh?](https://github.com/charmbracelet/huh), [Log](https://github.com/charmbracelet/log) and [golang.org/x/crypto](https://golang.org/x/crypto). The interface is a simple and self-explanatory TUI form. The output can be either a Base64 encoded string or a very simple custom file format, depending on what you're encrypting.

Originally I was also going to implement asymmetric encryption (RSA and maybe something based on Curve25519), but I decided against it, since tools like GPG already exist for that. I may implement it in the future, but I probably won't.
