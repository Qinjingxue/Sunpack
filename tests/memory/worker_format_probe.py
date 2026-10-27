"""Manual, child-Job-bounded coverage of every supported container/codec family.

This is not a benchmark test or a default pytest suite. Real worker commitment
and recovery are independent of the small functional format tests. Reuse their
fixture encoders, and compare every byte count/CRC32 to the original payload.
"""
import argparse
import binascii
import json
import lzma
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.memory import worker_reserve_probe as probe
from tests.helpers.native_fixture import file_inventory, native_fixture
from tests.helpers.generated_fixtures import write_single_method_zip
from tests.helpers.real_archives import create_compression_stream
from tests.helpers.tool_config import require_7z, require_7z_zstd, get_optional_rar


def generate(folder):
    folder.mkdir(parents=True, exist_ok=True)
    source = folder / 'source'
    source.mkdir(exist_ok=True)
    payload = source / 'payload.bin'
    if not payload.exists():
        # Test fixture IO only, bounded to one 2 MiB file.
        payload.write_bytes(bytes(range(256)) * 8192)
    expected = [(v['size'], v['crc32']) for v in file_inventory(source).values()]
    cases = []

    def pack(name, hint, tool, options, input_path=payload, password=None, reference=None):
        archive = folder / (name + '.' + hint)
        if not archive.exists():
            box = probe.Sandbox(512, cpu_rate=1000)
            try:
                p = subprocess.Popen([str(tool), *options, str(archive), str(input_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                box.assign(p)
                stdout, stderr = p.communicate(timeout=60)
                assert p.returncode == 0, (name, stdout[-1000:], stderr[-1000:])
            finally:
                box.close()
        cases.append((name, archive, hint, expected if reference is None else reference, password))

    seven = require_7z()
    for method in ('Copy', 'Deflate', 'Deflate64', 'BZip2', 'LZMA', 'PPMd'):
        pack('zip-' + method, 'zip', seven, ['a', '-tzip', '-mx=5', '-mmt=2', '-mm=' + method])
    for method in ('Copy', 'LZMA', 'LZMA2', 'PPMd', 'BZip2', 'Deflate'):
        pack('7z-' + method, '7z', seven, ['a', '-t7z', '-mx=5', '-mmt=2', '-m0=' + method])
    pack('7z-LZ4', '7z', require_7z_zstd(), ['a', '-t7z', '-mmt=2', '-m0=LZ4'])
    pack('7z-BCJ2', '7z', seven, ['a', '-t7z', '-mmt=2', '-m0=BCJ2', '-m1=LZMA2', '-m2=LZMA2', '-m3=LZMA2', '-mb0:1', '-mb0s1:2', '-mb0s2:3'])
    # Four legal 3 MiB dictionaries stay below the 4 MiB managed threshold.
    # A single small source would let the encoder reduce their properties and
    # would miss the aggregate commitment of a complete BCJ2 graph.
    multi = folder / 'bcj2-small-dictionaries.bin'
    if not multi.exists(): multi.write_bytes(bytes(range(256)) * 12288)
    multi_expected = [(v['size'], v['crc32']) for k, v in file_inventory(folder).items() if k == multi.name]
    pack('7z-BCJ2-four-small-dictionaries', '7z', seven,
        ['a', '-t7z', '-mmt=2', '-m0=BCJ2', *('-m' + str(i) + '=LZMA2:d=3m' for i in range(1, 5)),
         '-mb0:1', '-mb0s1:2', '-mb0s2:3', '-mb0s3:4'], input_path=multi, reference=multi_expected)
    near = folder / 'bcj2-near-threshold.bin'
    if not near.exists(): near.write_bytes(bytes(range(256)) * 16384)
    near_expected = [(v['size'], v['crc32']) for k, v in file_inventory(folder).items() if k == near.name]
    # The encoder rounds LZMA properties up to 4 MiB. The format also permits
    # page-aligned smaller dictionaries; this repetitive input needs only short
    # matches. Rewrite the four properties in an uncompressed header and repair
    # both header CRCs. Output CRC is still checked against the original file.
    for name, dictionary in (('subthreshold', (4 << 20) - 4096), ('unmanaged', (2 << 20) - 4096)):
        pack('7z-BCJ2-four-' + name + '-dictionaries', '7z', seven,
            ['a', '-t7z', '-mhc=off', '-mmt=2', '-m0=BCJ2', *('-m' + str(i) + '=LZMA:d=4m' for i in range(1, 5)),
             '-mb0:1', '-mb0s1:2', '-mb0s2:3', '-mb0s3:4'], input_path=near, reference=near_expected)
        archive = cases[-1][1]
        data = bytearray(archive.read_bytes())
        offset, size = struct.unpack_from('<QQ', data, 12)
        header = data[32 + offset:32 + offset + size]
        old, new = b'\x5d' + struct.pack('<I', 4 << 20), b'\x5d' + struct.pack('<I', dictionary)
        if header.count(old) == 4:
            data[32 + offset:32 + offset + size] = header.replace(old, new)
            struct.pack_into('<I', data, 28, binascii.crc32(data[32 + offset:32 + offset + size]))
            struct.pack_into('<I', data, 8, binascii.crc32(data[12:32]))
            archive.write_bytes(data)
        else:
            assert header.count(new) == 4, 'expected four explicit LZMA dictionary properties'
    for filter_name in ('BCJ', 'ARM', 'ARMT', 'ARM64', 'PPC', 'IA64', 'SPARC', 'RISCV', 'Delta'):
        pack('7z-' + filter_name, '7z', seven, ['a', '-t7z', '-mmt=2', '-m0=' + filter_name, '-m1=LZMA2'])
    # Independent legal ZIP payloads for decode-only methods. LZFSE's raw block
    # exercises its ordinary decoder/window without needing another encoder.
    raw = payload.read_bytes()
    for method, name, packed in (
        (95, 'zip-XZ', lzma.compress(raw)),
        (99, 'zip-LZFSE', b'bvx-' + struct.pack('<I', len(raw)) + raw + b'bvx$'),
    ):
        archive = folder / (name + '.zip')
        write_single_method_zip(archive, raw, packed, method)
        cases.append((name, archive, 'zip', expected, None))
    archive = folder / 'zip-Zstd.zip'
    reference = native_fixture('zip_method', output=str(archive), method=93)['expected_files']
    cases.append(('zip-Zstd', archive, 'zip', [(v['size'], v['crc32']) for v in reference.values()], None))
    pack('zip-AES', 'zip', seven, ['a', '-tzip', '-mmt=2', '-mem=AES256', '-psunpack-test'], password='sunpack-test')
    pack('zip-ZipCrypto', 'zip', seven, ['a', '-tzip', '-mmt=2', '-mem=ZipCrypto', '-psunpack-test'], password='sunpack-test')
    pack('7z-AES', '7z', seven, ['a', '-t7z', '-mmt=2', '-mhe=on', '-psunpack-test'], password='sunpack-test')
    rar = get_optional_rar()
    assert rar, 'configure the existing RAR fixture writer'
    for version in (4, 5):
        pack('rar' + str(version), 'rar', rar, ['a', '-idq', '-ep1', '-ma' + str(version), '-m5', '-mt2'])
    tar = folder / 'payload.tar'
    if not tar.exists():
        subprocess.run([str(seven), 'a', '-ttar', str(tar), str(payload)], check=True, stdout=subprocess.DEVNULL)
    cases.append(('tar', tar, 'tar', expected, None))
    tar_expected = [(v['size'], v['crc32']) for k, v in file_inventory(folder).items() if k == tar.name]
    for fmt in ('gzip', 'bzip2', 'xz', 'zstd', 'lz4'):
        for label, original, reference in ((fmt, payload, expected), ('tar-' + fmt, tar, tar_expected)):
            archive = folder / (label + '.stream')
            if not archive.exists():
                create_compression_stream(original, archive, fmt)
            cases.append((label, archive, fmt, reference, None))
    data = ROOT / 'native/sunpack_enc/tests/data'
    enc_expected = [(v['size'], v['crc32']) for k, v in file_inventory(data).items() if k == 'expected.zip']
    for name in [*(f'algorithm_{i}.mov' for i in range(10)), 'params_01.enc', 'params_10.enc']:
        cases.append(('enc-' + Path(name).stem, data / name, 'enc', enc_expected, 'sunpack-test'))
    return cases


def corpus_cases(corpus):
    cases = []
    for archive in sorted(corpus.iterdir()):
        hint = archive.suffix.lstrip('.').lower()
        if hint not in ('7z', 'zip', 'rar'): continue
        output = corpus / (archive.name + '-reference')
        box = probe.Sandbox(512, cpu_rate=1000)
        try:
            p = subprocess.Popen([str(require_7z()), 'x', '-y', '-mmt=2', '-o' + str(output), str(archive)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            box.assign(p)
            stdout, stderr = p.communicate(timeout=60)
            assert p.returncode == 0, (archive, stdout[-1000:], stderr[-1000:])
        finally:
            box.close()
        reference = [(v['size'], v['crc32']) for v in file_inventory(output).values()]
        cases.append(('corpus-' + archive.stem, archive, hint, reference, None))
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'reports/worker-memory-optimization-20261027')
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--case', action='append')
    parser.add_argument('--generate-only', action='store_true')
    parser.add_argument('--corpus', type=Path, help='optional independent legacy ZIP/RAR/7z samples')
    args = parser.parse_args()
    probe.OUT = args.report_dir.resolve()
    cases = generate(probe.OUT / 'fixtures')
    if args.corpus: cases.extend(corpus_cases(args.corpus.resolve()))
    (probe.OUT / 'cases.json').write_text(json.dumps([
        {'name': name, 'archive': str(path), 'format': fmt, 'expected': expected, 'password': password}
        for name, path, fmt, expected, password in cases], indent=2))
    if not args.generate_only:
        for name, archive, fmt, expected, password in cases:
            if args.case and name not in args.case: continue
            probe.run(name, archive, fmt, args.jobs, expected_output=expected, password=password)
