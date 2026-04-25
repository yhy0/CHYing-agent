# FFmpeg discovered to contain a code injection vulnerability in the component net.bramp.ffmpeg.FFmpeg.<constructor>

**GHSA**: GHSA-2jx3-fx5f-r2c6 | **CVE**: CVE-2023-39018 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **net.bramp.ffmpeg:ffmpeg** (maven): <= 0.7.0

## Description

## Withdrawn

This advisory has been withdrawn because it has been found to be disputed. Please see the issue [here](https://github.com/bramp/ffmpeg-cli-wrapper/issues/291) for more information.

## Original Despcription 

FFmpeg 0.7.0 and below was discovered to contain a code injection vulnerability in the component net.bramp.ffmpeg.FFmpeg.<constructor>. This vulnerability is exploited via passing an unchecked argument.
