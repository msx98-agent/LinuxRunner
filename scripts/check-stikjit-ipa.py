import plistlib
import sys
import zipfile

print('check-stikjit-ipa.py:start: checking packaged helper and framework')
with zipfile.ZipFile(sys.argv[1]) as ipa:
    print('check-stikjit-ipa.py:archive: opened IPA')
    helper = 'Payload/LinuxRunner.app/PlugIns/StikJITHelper.appex/'
    info = plistlib.loads(ipa.read(helper + 'Info.plist'))
    assert info['CFBundleIdentifier'].endswith('.StikJITHelper'), info
    assert info['NSExtension']['NSExtensionPrincipalClass'] == 'StikJITHelper.RequestHandler', info
    assert tuple(map(int, info['MinimumOSVersion'].split('.'))) >= (17, 4), info
    assert len(ipa.read(helper + 'StikJITHelper')) > 0
    assert len(ipa.read(helper + 'Frameworks/StikJIT.framework/StikJIT')) > 0
    assert len(ipa.read(helper + 'Frameworks/StikJIT.framework/universal.js')) > 0
    app = plistlib.loads(ipa.read('Payload/LinuxRunner.app/Info.plist'))
    assert '_remotepairing._tcp' in app['NSBonjourServices'], app
    assert app['NSLocalNetworkUsageDescription'], app
    print('check-stikjit-ipa.py:archive:end: helper, framework, universal script and network declarations verified')
print('check-stikjit-ipa.py:complete: success')
