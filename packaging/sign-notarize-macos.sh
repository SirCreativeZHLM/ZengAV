#!/bin/zsh
# Re-sign the macOS release zips with a Developer ID, notarize, staple, and re-upload them.
# Needs: the Developer ID certificate in the login keychain, and a notarytool keychain profile:
#   xcrun notarytool store-credentials zengav-notary --apple-id <apple id> --team-id <team id>
# Usage: packaging/sign-notarize-macos.sh v0.2.0
set -euo pipefail
TAG=${1:?usage: sign-notarize-macos.sh <tag>}
REPO=SirCreativeZHLM/ZengAV
PROFILE=${NOTARY_PROFILE:-zengav-notary}
ID=${SIGN_IDENTITY:-"Developer ID Application: WEISHENG WANG (Y258G9Q3M8)"}
HERE=${0:A:h}
WORK=$(mktemp -d)
cat > $WORK/ent.plist <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.allow-jit</key><true/>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
</dict></plist>
PL
for ARCH in arm64 x64; do
  NAME=ZengAV-macos-$ARCH
  D=$WORK/$ARCH; mkdir -p $D; cd $D
  gh release download $TAG -R $REPO -p "$NAME.zip"
  unzip -q $NAME.zip; rm $NAME.zip
  for T in zengav ZengAV.app/Contents/MacOS/ZengAV ZengAV.app; do
    codesign --force --options runtime --timestamp --entitlements $WORK/ent.plist --sign "$ID" $T
  done
  codesign --verify --deep --strict ZengAV.app
  ditto -c -k --keepParent ZengAV.app submit.zip
  xcrun notarytool submit submit.zip --keychain-profile "$PROFILE" --wait
  xcrun stapler staple ZengAV.app
  xcrun stapler validate ZengAV.app
  spctl --assess --type execute --verbose ZengAV.app
  rm submit.zip
  zip -qry $NAME.zip ZengAV.app zengav
  shasum -a 256 $NAME.zip > $NAME.zip.sha256
  gh release upload $TAG $NAME.zip $NAME.zip.sha256 -R $REPO --clobber
done
echo "Done: both macOS downloads are signed, notarized and stapled."
