# REPOSITORY CONTENT #

This repository contains code for the paper:

"Broken Fingers: On the Usage of the Fingerprint API in Android"

presented at the:

2018 Network & Distributed System Security Symposium (NDSS)

# Cite
```
@inproceedings{bianchi2018brokenfingers,
  title={{Broken Fingers: On the Usage of the Fingerprint API in Android}},
  author={Bianchi, Antonio and Fratantonio, Yanick and Machiry, Aravind and Kruegel, Christopher and Vigna, Giovanni and Chung, Simon Pak Ho and Lee, Wenke},
  booktitle={Proceedings of the Annual Network \& Distributed System Security Symposium (NDSS)},
  year=2018
}
```

# Compile
``` bash
./compile.py
```
The resulting jar will be saved in `SootAnalysis.jar`.

A pre-compiled `SootAnalysis.jar` is provided.

This code has been compiled and tested using `openjdk` version `1.8`.
# Run
``` bash
java -jar SootAnalysis.jar fp1 <android_sdk_platforms> <apk> | ./postprocessing.py - | grep " FINAL_RESULT"
```
`<apk>`: The Android APK file you want to analyze.

`<android_sdk_platforms>`: A folder containing platform files from the Android SDK.
This folder is typically somethig like `HOME/Android/Sdk/platforms/` and it contains sub-folders like `android-X`, where `X` is a different Android SDK version.
Analyzing an APK targeting version `X` requires you to have the `android-X` folder in `<android_sdk_platforms>`.

Running the command line above will print one of these three values: `WEAK`, `DECRYPTION`, or `SIGN`.

