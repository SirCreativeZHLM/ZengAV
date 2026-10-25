#!/bin/zsh
# Re-sign the macOS release zips with a Developer ID, notarize them through the Apple ID that is
# signed in to Xcode, staple, and re-upload. Needs Xcode.app signed in to the developer team and the
# Developer ID Application certificate in the login keychain.
# Usage: packaging/sign-notarize-macos.sh v0.2.0
set -euo pipefail
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
TAG=${1:?usage: sign-notarize-macos.sh <tag>}
REPO=SirCreativeZHLM/ZengAV
TEAM=${TEAM_ID:-Y258G9Q3M8}
ID=${SIGN_IDENTITY:-"Developer ID Application: WEISHENG WANG ($TEAM)"}
VERSION=${TAG#v}
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
cat > $WORK/opts.plist <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>method</key><string>developer-id</string><key>destination</key><string>upload</string>
<key>teamID</key><string>$TEAM</string><key>signingStyle</key><string>manual</string>
<key>signingCertificate</key><string>Developer ID Application</string>
</dict></plist>
PL
for ARCH in arm64 x64; do
  NAME=ZengAV-macos-$ARCH
  D=$WORK/$ARCH; mkdir -p $D; cd $D
  gh release download $TAG -R $REPO -p "$NAME.zip"; unzip -q $NAME.zip; rm $NAME.zip
  A=$D/ZengAV.xcarchive; mkdir -p $A/Products/Applications; mv ZengAV.app $A/Products/Applications/
  APP=$A/Products/Applications/ZengAV.app
  cp zengav $APP/Contents/Resources/zengav   # embedded (not in MacOS: ZengAV and zengav are the same name on macOS) so the CLI is covered by the same ticket
  for T in $APP/Contents/Resources/zengav $APP/Contents/MacOS/ZengAV $APP; do
    codesign --force --options runtime --timestamp --entitlements $WORK/ent.plist --sign "$ID" $T
  done
  codesign --verify --deep --strict $APP
  cat > $A/Info.plist <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>ApplicationProperties</key><dict>
<key>ApplicationPath</key><string>Applications/ZengAV.app</string><key>CFBundleIdentifier</key><string>com.zengbot.zengav</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string><key>CFBundleVersion</key><string>$VERSION</string>
<key>SigningIdentity</key><string>$ID</string><key>Team</key><string>$TEAM</string></dict>
<key>ArchiveVersion</key><integer>2</integer><key>Name</key><string>ZengAV</string><key>SchemeName</key><string>ZengAV</string></dict></plist>
PL
  xcodebuild -exportArchive -archivePath $A -exportOptionsPlist $WORK/opts.plist -exportPath $D/out
  # Apple processes the upload; poll until it is ready, then export the stapled app.
  until xcodebuild -exportNotarizedApp -archivePath $A -exportPath $D/notarized >/dev/null 2>&1; do sleep 60; rm -rf $D/notarized; done
  spctl --assess --type execute --verbose $D/notarized/ZengAV.app
  cd $D/notarized
  cp $APP/Contents/Resources/zengav ./zengav
  zip -qry $D/$NAME.zip ZengAV.app zengav
  cd $D && shasum -a 256 $NAME.zip > $NAME.zip.sha256
  gh release upload $TAG $NAME.zip $NAME.zip.sha256 -R $REPO --clobber
done
echo "Done: both macOS downloads are signed, notarized and stapled."
