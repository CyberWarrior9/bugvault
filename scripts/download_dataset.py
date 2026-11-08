#!/usr/bin/env python3
"""Download HackerOne's official disclosed-reports dataset (parquet).

Source: https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports
Published by HackerOne themselves. Train split only (~15MB, 10,094 reports).
"""
import sys
import urllib.request

URL = ("https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports"
       "/resolve/refs%2Fconvert%2Fparquet/default/train/0000.parquet")
OUT = "h1_train.parquet"


def main():
    print(f"downloading {URL}")
    urllib.request.urlretrieve(URL, OUT)
    import os
    size = os.path.getsize(OUT)
    print(f"saved {OUT} ({size:,} bytes)")
    print("verify with: python3 scripts/analyze_corpus.py")


if __name__ == "__main__":
    main()
