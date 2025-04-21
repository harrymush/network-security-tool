# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['network_security_tool/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('network_security_tool/data', 'data'),
    ],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtWidgets',
        'PyQt6.QtGui',
        'scapy.all',
        'nmap',
        'whois',
        'dns',
        'dns.resolver',
        'cryptography',
        'requests',
        'network_security_tool.gui',
        'network_security_tool.scanner',
        'network_security_tool.sniffer',
        'network_security_tool.analysis',
        'network_security_tool.generator',
        'network_security_tool.cracker',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Network Security Tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=True,
    target_arch='x86_64',
    codesign_identity=None,
    entitlements_file=None,
    icon='network_security_tool/data/app_icon.icns',
)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='Network Security Tool.app',
    icon='network_security_tool/data/app_icon.icns',
    bundle_identifier='com.networksecurity.tool',
    info_plist={
        'NSHighResolutionCapable': 'True',
        'LSBackgroundOnly': 'False',
        'NSRequiresAquaSystemAppearance': 'False',
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleVersion': '1.0.0',
        'CFBundleName': 'Network Security Tool',
        'CFBundleDisplayName': 'Network Security Tool',
        'CFBundleGetInfoString': 'Network Security Tool',
        'CFBundleIdentifier': 'com.networksecurity.tool',
        'NSAppleEventsUsageDescription': 'This app requires access to run system commands.',
        'NSSystemAdministrationUsageDescription': 'This app requires administrative privileges for network operations.',
    },
) 