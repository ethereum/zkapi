import assert from 'node:assert/strict';
import test from 'node:test';
import { browserSdkOptions, configureBrowserSdk } from '../configure.js';

test('the host\'s provider-key policy is accepted as two functions and nothing else', () => {
    const before = browserSdkOptions();
    assert.equal(before.verifyProviderKey, null);
    assert.equal(before.assertProviderKey, null);
    const verify = async () => ({ status: 'verified' });
    const assert_ = () => {};
    configureBrowserSdk({ verifyProviderKey: verify, assertProviderKey: assert_ });
    assert.equal(browserSdkOptions().verifyProviderKey, verify);
    assert.equal(browserSdkOptions().assertProviderKey, assert_);
    assert.throws(() => configureBrowserSdk({ verifyProviderKey: 'yes' }), /verifyProviderKey must be a provider verification function/);
    assert.throws(() => configureBrowserSdk({ assertProviderKey: {} }), /assertProviderKey must be a provider verification function/);
    // An option the SDK does not know is still refused by name.
    assert.throws(() => configureBrowserSdk({ verifyProvider: verify }), /Unknown zkAPI browser SDK option: verifyProvider/);
    configureBrowserSdk({ verifyProviderKey: null, assertProviderKey: null });
});
