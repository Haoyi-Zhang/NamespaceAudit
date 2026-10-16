"""Regenerate the schematic set twice and check vector/font structure."""
import subprocess
import sys
import tempfile
from pathlib import Path
from pypdf import PdfReader

NAMES = ('checker-pipeline','nonlocal-composition','recovery-order')

def main():
    generator=Path(__file__).with_name('plot_schematics.py')
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        for folder in ('first','second'):
            subprocess.run([sys.executable,'-B',str(generator),'--outdir',str(root/folder)],check=True)
        for name in NAMES:
            a=root/'first'/(name+'.pdf');b=root/'second'/(name+'.pdf')
            if a.read_bytes()!=b.read_bytes():
                raise AssertionError('non-deterministic output: '+name)
            reader=PdfReader(a)
            if len(reader.pages)!=1:
                raise AssertionError('not a single-page figure: '+name)
            page=reader.pages[0]
            resources=page['/Resources'].get_object()
            for obj in resources.get('/XObject',{}).get_object().values():
                if obj.get_object().get('/Subtype')=='/Image':
                    raise AssertionError('raster image: '+name)
            fonts=resources.get('/Font',{}).get_object()
            if not fonts:
                raise AssertionError('missing fonts: '+name)
            for font in fonts.values():
                font=font.get_object()
                targets=font.get('/DescendantFonts',[font])
                for target in targets:
                    descriptor=target.get_object().get('/FontDescriptor')
                    if not descriptor or not any(k in descriptor.get_object() for k in ('/FontFile','/FontFile2','/FontFile3')):
                        raise AssertionError('unembedded font: '+name)
        print('Three deterministic namespace vector figures with embedded fonts: PASS')

if __name__=='__main__':
    main()
