import os.path

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

excluded_dlls = {'opengl32sw.dll', 'Qt6Quick.dll'}

filtered_binaries = []
for bin_item in a.binaries:
    # bin_item is a tuple like (path_to_dll, destination_folder, type)
    if os.path.basename(bin_item[0]).lower() not in excluded_dlls:
        filtered_binaries.append(bin_item)

a.binaries = filtered_binaries

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='convert-images',
)
