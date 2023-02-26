# WinDumb2Pty

An agent that upgrade a dumb windows tcp remote shell with a pty by leveraging Windows ConPTY API.
It is based on [antonioCoco's ConPtyShell PoC](https://github.com/antonioCoco/ConPtyShell) but implemented natively (C++)

## Usage

Usage: **windump2pty.exe** *PROGRAM ROWS COLS POPENMODECODE PTYMODECODE*

PROGRAM: Path of the program to start in the pty console

COLS: number of column for the pty console

ROWS: number of rows for the pty console

POPENMODECODE: control code to receive in order to switch to popen mode

PTYMODECODE: control code to receive in order to switch to pty mode


## features

The agent has two modes:
* The pty mode for interacting with an instance of an arbitrary program.
* The popen mode for executing automated remote commands.

The agent always start in pty mode.

Note: Upon switching to popen mode, The agent will try to synchronize its current working directory with the program launched in the pty console. This is done by sending the command "cmd /c cd" to the pty console. 
If no valid directory path is returned, the current working directory isn't changed.


## Limitations

* As the agent leverage the Windows ConPTY API and more specifically the CreatePseudoConsole() function, it works only Windows 10 / Windows Server 2019 version 1809 (build 10.0.17763) or later.
* Only x64 systems are supported.
* Doesn't work with ssl remote shells

Warning: the pty agent is not a C2 implant for red team engagement, hence it's not very much opsec.

