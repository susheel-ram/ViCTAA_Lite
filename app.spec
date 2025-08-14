# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['app.py'],  # Include both app.py and gui.py
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),  # Include templates folder
        ('static', 'static')         # Include static folder

    ],
    hiddenimports=[
        
        # ReportLab Barcode Dependencies
        'reportlab.graphics.barcode',
        'reportlab.graphics.barcode.code128',
        'reportlab.graphics.barcode.code39',
        'reportlab.graphics.barcode.code93',
        'reportlab.graphics.barcode.usps',
        'reportlab.graphics.barcode.usps4s',
        'reportlab.graphics.barcode.eanbc',
        'reportlab.graphics.barcode.common',
        'reportlab.graphics.barcode.itf',
        'reportlab.graphics.barcode.widgets',
        'reportlab.graphics.barcode.qr',
        'reportlab.graphics.barcode.ecc200datamatrix',
        'reportlab.graphics.barcode.code11',
        'reportlab.graphics.barcode.postnet',
        'reportlab.graphics.barcode.msi',
        'reportlab.graphics.barcode.cbc',

        # General ReportLab Dependencies
        'reportlab.lib.utils',
        'reportlab.lib.rl_accel',
        'reportlab.platypus.tables',
        'reportlab.pdfgen.canvas',
        'reportlab.graphics.shapes',
        'reportlab.graphics.renderPDF',

        # xhtml2pdf Dependencies
        'xhtml2pdf',
        'xhtml2pdf.context',
        'xhtml2pdf.document',
        'xhtml2pdf.parser',
        'xhtml2pdf.tags',
        'xhtml2pdf.xhtml2pdf_reportlab',
        'eventlet', 'pysqlite2', 'MySQLdb', 'gevent', 'gevent-websocket',
        #'eventlet.hubs.epolls', 'eventlet.hubs.kqueue', 
        #'eventlet.hubs.selects',
        #'eventlet.patcher', 
        #'eventlet.greenpool', 
        #'eventlet.queue', 
        #'eventlet.tpool', 'eventlet.green', 'dns.dnssec',
        #'dns.resolver',
        #'dns.query',
        #'dns.message',
        #'eventlet.greenlet',
        #'eventlet.greenpool',
        #'eventlet.hubs',
        #'eventlet.queue',
        #'eventlet.support.greenlets',
        #'eventlet.support.greennds',
        #'eventlet.support.greenio', 'dns.e164',
        #'greenlet.greenlet',
        #'eventlet.green.socket',
        #'eventlet.greenio',
        #'werkzeug.local',
        #'requests.adapters', 'dns.namedict', 'dns.tsigkeyring', 'dns', 'eventlet.green.dns', 'dns.versioned', 'dns.rdtypes',
        #'dns.rdtypes.ANY', 'dns.rrset', 'dns.exception',
        'engineio.async_drivers.threading'

    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ViCTAA_Lite',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['static\\LapSec1.png'],  # Path to the application icon
    onefile=True, 
)

#coll = COLLECT(
#    exe,
#    a.binaries,
#    a.zipfiles,
#    a.datas,
#    strip=False,
#    upx=True,
#    name='ViCTAA'
#)