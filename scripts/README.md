# NativeDNS build scripts

## Windows

```bat
windows\build-debug.bat [standalone|portable|installer|all]
windows\build-release.bat [standalone|portable|installer|all]
```

Both wrappers default to `all`.

Generic entry point:

```bat
windows\build-windows.bat <debug|release> <standalone|portable|installer|all>
```

Packaging:
- standalone: staged runnable directory;
- portable: ZIP;
- installer: Inno Setup EXE.

Qt 6 MSVC x64 is required. Set `QT_ROOT` if `windeployqt` is not already in PATH.

## Linux

```bash
./linux/build-debug.sh [standalone|portable|appimage|deb|all]
./linux/build-release.sh [standalone|portable|appimage|deb|all]
```

Both wrappers default to `all`.

Generic entry point:

```bash
./linux/build-linux.sh <debug|release> <standalone|portable|appimage|deb|all>
```

Packaging:
- standalone: CMake install tree;
- portable: tar.gz AppDir bundle;
- appimage: AppImage;
- deb: Debian package.

Install Debian/Ubuntu build dependencies with `linux/install-build-deps-debian.sh`.
AppImage/portable deployment additionally requires `linuxdeploy` and `linuxdeploy-plugin-qt`.
