# -*- coding: utf-8 -*-

'''
Stores and retrieves arbitrary data inside the Extra field of an APK/ZIP
archive without invalidating the APK signature. Know that this embedding does
not work for APKv2 signed APKs, because that signature type also protects the
integrity of the ZIP central directory, in which the Extra fields are stored.

# Example Usage

On a new Android project:
- Call `python3 -m apk_metadata prepare /path/to/android/project` to generate the appropriate files with hints,
- Build the project,
- Sign the APK with V1 signature (not V2 or V3),
- Call `python3 -m apk_metadata write /path/to/signed.apk /path/to/modified.apk` to write the payload,
- Call `python3 -m apk_metadata read /path/to/modified.apk` to extract the payload.
'''
