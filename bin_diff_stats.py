#!/usr/bin/env python3
# bin_diff_stats.py — binary similarity comparison with aligned/unaligned modes

import argparse
import os
import sys
import mmap
import difflib


def format_with_commas(number: int) -> str:
    return f"{number:,}"


def scan_aligned(file_a_bytes: memoryview, file_b_bytes: memoryview, min_block_length: int):
    """Return overlap, identical_count, and ranges comparing same-offset bytes."""
    overlap_length = min(len(file_a_bytes), len(file_b_bytes))
    identical_count = 0
    identical_ranges = []
    index = 0

    while index < overlap_length:
        if file_a_bytes[index] == file_b_bytes[index]:
            start_offset = index
            index += 1
            while index < overlap_length and file_a_bytes[index] == file_b_bytes[index]:
                index += 1
            block_length = index - start_offset
            if block_length >= min_block_length:
                identical_ranges.append((start_offset, block_length))
            identical_count += block_length
        else:
            index += 1

    return overlap_length, identical_count, identical_ranges


def scan_unaligned(file_a: bytes, file_b: bytes, min_block_length: int, top_n: int):
    """Find matching blocks even if moved, using difflib."""
    matcher = difflib.SequenceMatcher(None, file_a, file_b, autojunk=False)
    blocks = [
        block for block in matcher.get_matching_blocks()
        if block.size >= min_block_length
    ]  # last block has size 0 sentinel
    identical_total = sum(block.size for block in blocks)
    sorted_blocks = sorted(blocks, key=lambda b: b.size, reverse=True)
    return identical_total, sorted_blocks[:top_n], blocks


def main():
    parser = argparse.ArgumentParser(
        description="Compare two binaries and report % identical/different and identical block stats.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file_a_path")
    parser.add_argument("file_b_path")
    parser.add_argument("--min-block", type=int, default=1, help="Minimum identical block length to report")
    parser.add_argument("--top", type=int, default=10, help="Show top N longest identical blocks")
    parser.add_argument("--csv", type=str, default=None, help="Write identical blocks to CSV")
    parser.add_argument("--unaligned", action="store_true",
                        help="Find identical blocks even if moved (uses difflib; slower & memory-heavy)")
    args = parser.parse_args()

    try:
        with open(args.file_a_path, "rb") as file_a, open(args.file_b_path, "rb") as file_b:
            len_a = os.fstat(file_a.fileno()).st_size
            len_b = os.fstat(file_b.fileno()).st_size

            mmap_a = mmap.mmap(file_a.fileno(), 0, access=mmap.ACCESS_READ) if len_a else None
            mmap_b = mmap.mmap(file_b.fileno(), 0, access=mmap.ACCESS_READ) if len_b else None

            print(f"\nFile A: {args.file_a_path} ({format_with_commas(len_a)} bytes)")
            print(f"File B: {args.file_b_path} ({format_with_commas(len_b)} bytes)\n")

            if args.unaligned:
                bytes_a = (memoryview(mmap_a)[:] if mmap_a else b"")
                bytes_b = (memoryview(mmap_b)[:] if mmap_b else b"")
                identical_total, top_blocks, all_blocks = scan_unaligned(
                    bytes_a, bytes_b, args.min_block, args.top
                )

                total_union = max(len_a, len_b)
                percent_identical = (identical_total / total_union * 100.0) if total_union else 0.0
                percent_different = 100.0 - percent_identical

                print(f"Identical bytes (unaligned): {format_with_commas(identical_total)}")
                print(f"Percent identical over union  : {percent_identical:.2f}%")
                print(f"Percent different over union  : {percent_different:.2f}%")

                if all_blocks:
                    longest_block = max(all_blocks, key=lambda b: b.size)
                    average_length = identical_total / float(len(all_blocks))
                    print(f"\nIdentical blocks (min length {args.min_block}): {len(all_blocks)}")
                    print(f"  Longest block: A@0x{longest_block.a:X} "
                          f"B@0x{longest_block.b:X}, length {format_with_commas(longest_block.size)} bytes")
                    print(f"  Average block length: {average_length:.1f} bytes")

                    print(f"\nTop {min(args.top, len(all_blocks))} identical blocks by length:")
                    for block in top_blocks:
                        print(f"  A@0x{block.a:X}  B@0x{block.b:X}  length {format_with_commas(block.size)}")

                    if args.csv:
                        with open(args.csv, "w", encoding="utf-8") as csv_file:
                            csv_file.write("startA_hex,startA_dec,startB_hex,startB_dec,length\n")
                            for block in all_blocks:
                                csv_file.write(f"0x{block.a:X},{block.a},0x{block.b:X},{block.b},{block.size}\n")
                        print(f"\nWrote identical blocks CSV -> {args.csv}")

            else:
                view_a = memoryview(mmap_a) if mmap_a else memoryview(b"")
                view_b = memoryview(mmap_b) if mmap_b else memoryview(b"")

                overlap_length, identical_count, identical_ranges = scan_aligned(
                    view_a, view_b, args.min_block
                )
                different_within_overlap = overlap_length - identical_count
                padding_difference = abs(len_a - len_b)
                total_union = max(len_a, len_b)

                percent_identical_overlap = (identical_count / overlap_length * 100.0) if overlap_length else 0.0
                percent_identical_union = (identical_count / total_union * 100.0) if total_union else 0.0
                percent_different_union = 100.0 - percent_identical_union
                jaccard_similarity = (
                    identical_count / (len_a + len_b - identical_count) * 100.0
                    if (len_a + len_b - identical_count) else 0.0
                )

                print(f"Overlap bytes: {format_with_commas(overlap_length)}")
                print(f"Identical bytes within overlap: {format_with_commas(identical_count)}")
                print(f"Different bytes within overlap: {format_with_commas(different_within_overlap)}")
                print(f"Extra bytes (length mismatch): {format_with_commas(padding_difference)}\n")

                print(f"Percent identical over overlap: {percent_identical_overlap:.2f}%")
                print(f"Percent identical over union  : {percent_identical_union:.2f}% (counts extra bytes as different)")
                print(f"Percent different over union  : {percent_different_union:.2f}%")
                print(f"Jaccard similarity (ident / (A+B-ident)) : {jaccard_similarity:.2f}%")

                if identical_ranges:
                    total_blocks = len(identical_ranges)
                    longest_block = max(identical_ranges, key=lambda t: t[1])
                    average_length = sum(length for _, length in identical_ranges) / float(total_blocks)

                    print(f"\nIdentical blocks (min length {args.min_block}): {total_blocks}")
                    print(f"  Longest block: offset 0x{longest_block[0]:X}, length {format_with_commas(longest_block[1])} bytes")
                    print(f"  Average block length: {average_length:.1f} bytes")

                    print(f"\nTop {min(args.top, total_blocks)} identical blocks by length:")
                    for offset, block_length in sorted(identical_ranges, key=lambda t: t[1], reverse=True)[:args.top]:
                        print(f"  offset 0x{offset:X}  length {format_with_commas(block_length)}")
                else:
                    print(f"\nNo identical blocks >= {args.min_block} bytes.")

                if args.csv:
                    with open(args.csv, "w", encoding="utf-8") as csv_file:
                        csv_file.write("start_offset_hex,start_offset_dec,length\n")
                        for offset, block_length in identical_ranges:
                            csv_file.write(f"0x{offset:X},{offset},{block_length}\n")
                    print(f"\nWrote identical blocks CSV -> {args.csv}")

    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)
    except PermissionError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()