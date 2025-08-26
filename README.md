# GhidraSCMP

A Ghidra extension that provides a language spec for the
SC/MP processor.

## Features

* Contains a language spec for the SC/MP processor.

## How to install
1. Download a [prebuilt GhidraSCMP release](https://github.com/sigurasg/GhidraSCMP/releases), or build it yourself.
1. Start Ghidra
1. File -> Install Extensions
1. Press the plus icon ("Add extension")
1. Choose the built or downloaded GhidraSCMP zip file
1. Restart Ghidra when prompted to load the extension properly

## How to build

### With VS Code and Docker

Open the directory in a VS Code instance and then reopen it in a devcontainer.

In a new terminal window type
```
./gradlew
```

### Otherwise

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `dist` directory.



## License

Licensed under the Apache License, Version 2.0.
