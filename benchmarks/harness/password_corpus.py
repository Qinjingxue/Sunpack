"""Fixture matrix for the production password verifier and extraction CLI."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
import random
import shutil
import struct
import subprocess
import zlib

from benchmarks.harness.native_probe import run_runtime_probe
from benchmarks.harness.workspace import REPO_ROOT
from tests.helpers.real_archives import create_zip_multidisk_archive
from tests.helpers.tool_config import get_test_tools
from tests.real.enc_support import ENC_PASSWORD, ENC_VECTOR


# Valid ZipCrypto archives with one literal-coded member. Shrink uses 9-bit
# literals; Implode has complete length/distance trees and uncoded literals.
# The two keys for each fixture pass the header byte and contradict its prefix.
LEGACY_ZIP = {
    'zip-crypto-shrink': (
        '504b0304140001000100000000005c6285142b0000001b000000010000006118b4dcddb437b1eb05c77511'
        'cd307dfade3e0a0986dbbc296e6f094b6048a1744f5d7d2fd517a6462c96cc504b01021400140001000100'
        '000000005c6285142b0000001b00000001000000000000000000000000000000000061504b050600000000'
        '010001002f0000004a0000000000',
        ('legacy-collision-245', 'legacy-collision-1585'),
    ),
    'zip-crypto-implode': (
        '504b0304140001000600000000005c628514350000001b000000010000006118b4dcddb437b1eb05c77511'
        '9db2ebf3af9a3de06fa4c7fadb4fe6664a3d9d3ed826bf59f7af325f78901c6cf4d63646e32937842a504b'
        '01021400140001000600000000005c628514350000001b000000010000000000000000000000000000000000'
        '61504b050600000000010001002f000000540000000000',
        ('legacy-collision-234', 'legacy-collision-245'),
    ),
}


@dataclass(frozen=True)
class PasswordCase:
    path: Path
    format: str
    method: str | None
    password: str = ENC_PASSWORD
    parts: tuple[Path, ...] = ()
    rar_native: bool = False
    zip_spanned: bool = False
    carrier_start: int | None = None
    carrier_end: int | None = None
    candidate_prefix: str = 'wrong-candidate-'
    may_report_unsupported_password: bool = False
    prefix_collisions: tuple[str, ...] = ()

    def archive_input(self):
        if self.carrier_start is not None:
            mode = 'file_range'
            parts = [{'path': str(self.path), 'start': self.carrier_start, 'end': self.carrier_end}]
        elif self.parts:
            mode = 'native_volumes'
            parts = [{'path': str(path), 'start': 0, 'volume_number': i, 'canonical_name': path.name}
                     for i, path in enumerate(self.parts, 1)]
        else:
            return None
        return {'entry_path': str(self.path), 'format_hint': self.format, 'logical_name': '',
                'mode': mode, 'parts': parts, 'volume_attempts': None,
                'analysis': {'password_required': True, 'structure_complete': True,
                             'rar_native_volume': self.rar_native, 'zip_spanned': self.zip_spanned}}


def _vint(data, at):
    value = 0
    for shift in range(0, 64, 7):
        b = data[at]
        at += 1
        value |= (b & 127) << shift
        if not b & 128:
            return value, at
    raise ValueError('RAR5 fixture has an invalid variable-length integer')


def _encode_vint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def _omit_rar5_password_check(path, header_encrypted):
    """Turn off the optional check while preserving the writer's ciphertext and KDF."""
    data = path.read_bytes()
    def strip_check(start, end):
        version, flags_at = _vint(data, start)
        flags, kdf_at = _vint(data, flags_at)
        if version != 0 or not flags & 1:
            raise ValueError('Expected an optional RAR5 password check in the reference writer output')
        check_at = kdf_at + 17 + (0 if header_encrypted else 16)
        return (data[start:flags_at] + _encode_vint(flags & ~1)
                + data[kdf_at:check_at] + data[check_at + 12:end])

    block = 8
    while block < len(data):
        size, fields = _vint(data, block + 4)
        end = fields + size
        pos = fields
        kind, pos = _vint(data, pos)
        flags, pos = _vint(data, pos)
        extra_at = pos
        extra, pos = _vint(data, pos) if flags & 1 else (0, pos)
        extra_size_end = pos
        packed, pos = _vint(data, pos) if flags & 2 else (0, pos)
        replacement = None
        if header_encrypted and kind == 4:
            replacement = data[fields:pos] + strip_check(pos, end)
        elif not header_encrypted and kind == 2:
            pos = end - extra
            while pos < end:
                record_at = pos
                length, start = _vint(data, pos)
                record, pos = _vint(data, start)
                if record == 1:
                    stop = start + length
                    record_body = data[start:pos] + strip_check(pos, stop)
                    rewritten = _encode_vint(len(record_body)) + record_body
                    new_extra = extra - (stop - record_at) + len(rewritten)
                    replacement = (data[fields:extra_at] + _encode_vint(new_extra)
                                   + data[extra_size_end:record_at] + rewritten + data[stop:end])
                    break
                pos = start + length
        if replacement is not None:
            header = _encode_vint(len(replacement)) + replacement
            path.write_bytes(data[:block] + struct.pack('<I', zlib.crc32(header)) + header + data[end:])
            return
        block = end + packed
    raise ValueError('No RAR5 encryption record in the reference writer output')


def build_cases(root, formats, patterns, executable):
    tools = get_test_tools()
    source = root / 'source'
    source.mkdir()
    regular = source / 'payload.bin'
    regular.write_bytes((b'sunpack password benchmark payload\x00' * 32768)[:1024 * 1024])
    # The same corpus exercises LZMA2 uncompressed chunks and multistream BCJ2.
    random_payload = source / 'random.bin'
    random_payload.write_bytes(random.Random(3714).randbytes(1024 * 1024))
    branch_payload = source / 'instructions.bin'
    branch_payload.write_bytes(b'\x55\xe8\x00\x00\x00\x00\x90\xc3' * 131072)
    cases, skipped = {}, {}
    carriers = {'7z-data-lzma2': '7z', 'zip-aes-deflate': 'zip',
                'rar4-header': 'rar', 'rar5-header': 'rar', 'enc-v4': 'enc'}

    def selected(name, fmt):
        return fmt in formats and any(fnmatchcase(name, pattern) for pattern in patterns)

    def source_selected(name, fmt):
        return selected(name, fmt) or (name in carriers and selected(f'{name}-carrier', fmt))

    def generate(name, fmt, method, options, *, tool='seven_zip', payload=regular,
                 split_glob=None, without_check=False, password=ENC_PASSWORD,
                 candidate_prefix='wrong-candidate-', may_report_unsupported_password=False):
        if not source_selected(name, fmt):
            return
        writer = tools[tool]
        if writer is None or not writer.is_file():
            skipped[name] = f'Fixture generator unavailable: {writer}'
            return
        folder = root / name
        folder.mkdir()
        archive = folder / f'payload.{fmt}'
        result = subprocess.run([str(writer), *options, str(archive), payload.name],
                                cwd=payload.parent, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        parts = tuple(sorted(folder.glob(split_glob))) if split_glob else ()
        if result.returncode or not (parts if split_glob else archive.is_file()):
            skipped[name] = f'Generator exited {result.returncode}: {result.stdout.decode("utf-8", "replace").strip()}'
            return
        if without_check:
            _omit_rar5_password_check(archive, '-hp' + ENC_PASSWORD in options)
        cases[name] = PasswordCase(parts[0] if parts else archive, fmt, method, password,
                                   parts=parts, rar_native=fmt == 'rar' and bool(parts),
                                   candidate_prefix=candidate_prefix,
                                   may_report_unsupported_password=may_report_unsupported_password)

    def carrier(name, case):
        folder = root / name
        folder.mkdir()
        output = folder / 'carrier.jpg'
        prefix = b'opaque prefix\x00' * 23
        data = case.path.read_bytes()
        output.write_bytes(prefix + data + (b'opaque suffix' if case.format != 'enc' else b''))
        cases[name] = PasswordCase(output, case.format, case.method, case.password,
                                   carrier_start=len(prefix),
                                   carrier_end=len(prefix) + len(data) if case.format != 'enc' else None)

    seven = ['a', '-t7z', '-y', f'-p{ENC_PASSWORD}']
    generate('7z-header', '7z', '7z_encrypted_header', [*seven, '-mhe=on', '-m0=LZMA2'])
    generate('7z-data', '7z', '7z_member_only', [*seven, '-mhe=off', '-m0=Copy'])
    if selected('7z-data-copy-direct-key', '7z'):
        folder = root / '7z-data-copy-direct-key'
        folder.mkdir()
        archive = folder / 'payload.7z'
        shutil.copyfile(REPO_ROOT / 'tests/data/7z_all_tiny_crc_collision.7z', archive)
        cases['7z-data-copy-direct-key'] = PasswordCase(archive, '7z', '7z_member_only', 'secret')
    for codec in ('LZMA', 'LZMA2', 'PPMd', 'BZip2', 'Deflate', 'Deflate64', 'ZSTD', 'LZ4'):
        lower = codec.lower()
        generator = 'seven_zip_zstd' if codec in {'ZSTD', 'LZ4'} else 'seven_zip'
        generate(f'7z-data-{lower}', '7z', f'7z_{lower}_prefix',
                 [*seven, '-mhe=off', f'-m0={codec}', '-mx=1'], tool=generator)
    generate('7z-data-lzma2-random', '7z', '7z_lzma2_prefix',
             [*seven, '-mhe=off', '-m0=LZMA2', '-mx=1'], payload=random_payload)
    generate('7z-data-bcj2', '7z', '7z_bcj2_range',
             [*seven, '-mhe=off', '-m0=BCJ2', '-m1=LZMA2', '-m2=LZMA2', '-m3=LZMA2',
              '-mb0:1', '-mb0s1:2', '-mb0s2:3'], payload=branch_payload)
    generate('7z-data-split', '7z', '7z_lzma2_prefix',
             [*seven, '-mhe=off', '-m0=LZMA2', '-mx=1', '-v128k'], payload=random_payload,
             split_glob='payload.7z.*')

    for encryption in ('ZipCrypto', 'AES128', 'AES192', 'AES256'):
        family = 'zip-crypto' if encryption == 'ZipCrypto' else 'zip-aes'
        method = 'zipcrypto_header_byte' if encryption == 'ZipCrypto' else 'winzip_aes_password_verifier'
        zip_cmd = ['a', '-tzip', '-y', f'-p{ENC_PASSWORD}', f'-mem={encryption}']
        name = family if encryption in ('ZipCrypto', 'AES256') else f'zip-{encryption.lower()}'
        generate(name, 'zip', method, [*zip_cmd, '-mx=0'])
        if encryption in ('ZipCrypto', 'AES256'):
            for codec in ('Deflate', 'Deflate64', 'BZip2', 'LZMA', 'PPMd', 'XZ', 'ZSTD'):
                generate(f'{family}-{codec.lower()}', 'zip', method, [*zip_cmd, f'-mm={codec}'],
                         tool='seven_zip_zstd' if codec == 'ZSTD' else 'seven_zip',
                         may_report_unsupported_password=codec == 'PPMd')
    generate('zip-aes-split', 'zip', 'winzip_aes_password_verifier',
             ['a', '-tzip', '-y', f'-p{ENC_PASSWORD}', '-mem=AES256', '-mx=0', '-v128k'],
             payload=random_payload, split_glob='payload.zip.*')
    for name, (data, collisions) in LEGACY_ZIP.items():
        if selected(name, 'zip'):
            folder = root / name
            folder.mkdir()
            archive = folder / 'payload.zip'
            archive.write_bytes(bytes.fromhex(data))
            cases[name] = PasswordCase(archive, 'zip', 'zipcrypto_header_byte', prefix_collisions=collisions)
    if selected('zip-aes-spanned', 'zip'):
        writer = tools['seven_zip']
        if writer is None or not writer.is_file():
            skipped['zip-aes-spanned'] = f'Fixture generator unavailable: {writer}'
        else:
            case = create_zip_multidisk_archive(root, 'zip-aes-spanned', payload_size=1024 * 1024,
                                                password=ENC_PASSWORD, encryption='AES256')
            cases[case.case_id] = PasswordCase(case.entry_path, 'zip', 'winzip_aes_password_verifier',
                                              parts=tuple(case.metadata['volume_paths']), zip_spanned=True)

    for version in (4, 5):
        for protection in ('header', 'data'):
            rar = ['a', f'-ma{version}', f'-{"hp" if protection == "header" else "p"}{ENC_PASSWORD}']
            method = 'rar5_password_check' if version == 5 else (
                'rar4_header_structure' if protection == 'header' else 'rar4_compressed_stream')
            generate(f'rar{version}-{protection}', 'rar', method, [*rar, '-m1'], tool='rar_exe')
            if version == 5:
                generate(f'rar5-{protection}-no-check', 'rar',
                         'rar5_header_structure' if protection == 'header' else 'rar5_compressed_block',
                         [*rar, '-m1', '-qo-'], tool='rar_exe', without_check=True)
            if protection == 'data':
                generate(f'rar{version}-data-split', 'rar', method, [*rar, '-m1', '-v128k'],
                         tool='rar_exe', payload=random_payload, split_glob='payload.part*.rar')
    generate('rar4-data-stored', 'rar', None, ['a', '-ma4', '-m0', f'-p{ENC_PASSWORD}'], tool='rar_exe')
    long_password = 'sunpack-rar4-legacy-long-test-password'
    generate('rar4-header-long-password', 'rar', 'rar4_header_structure',
             ['a', '-ma4', '-m1', f'-hp{long_password}'], tool='rar_exe', password=long_password,
             candidate_prefix='wrong-rar4-legacy-long-password-')

    for algorithm in range(10):
        name = 'enc-v4' if algorithm == 0 else f'enc-v4-{algorithm}'
        if source_selected(name, 'enc'):
            folder = root / name
            folder.mkdir()
            archive = folder / 'payload.enc'
            source = ENC_VECTOR if algorithm == 0 else ENC_VECTOR.with_name(f'algorithm_{algorithm}.mov')
            shutil.copyfile(source, archive)
            cases[name] = PasswordCase(archive, 'enc', 'enc_v4_quick_block')

    for name, fmt, method in (
        *((f'zip-strong-{bits}', 'zip', 'zip_pkware_strong') for bits in (128, 192, 256)),
        ('rar5-empty-crc', 'rar', 'rar5_empty_member_mac'),
        ('rar5-empty-blake', 'rar', 'rar5_empty_member_mac'),
    ):
        if selected(name, fmt):
            folder = root / name
            folder.mkdir()
            archive = folder / f'payload.{fmt}'
            run_runtime_probe(executable, 'benchmark_reader::password_fixture',
                              {'path': str(archive), 'format': name, 'runs': 1})
            cases[name] = PasswordCase(archive, fmt, method, 'secret')

    for base, fmt in carriers.items():
        name = f'{base}-carrier'
        if selected(name, fmt):
            if base in cases:
                carrier(name, cases[base])
            else:
                skipped[name] = f'Source archive {base} unavailable: {skipped[base]}'
    return {name: case for name, case in cases.items() if selected(name, case.format)}, skipped
