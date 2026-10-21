// Which zkAPI build a page loads (design §10.5). The legacy note-bound build
// and the concession build share IndexedDB `zkapi-browser-wallet-v1` and its
// lock, and each runtime refuses to load over a runtime slot that another
// deployment's note holds. So the host reads the stored holdings first and
// import()s the legacy entry while a legacy runtime holds an open note, and
// the current entry otherwise. There is no multi-circuit loader: each package
// keeps its own WebAssembly, keys and worker under its own publicPath.

function loaderError(code, message) {
    return Object.assign(new Error(message), { code });
}

function checkBuilds(builds) {
    for (const name of ['legacy', 'current']) {
        const build = builds?.[name];
        if (!build || typeof build.deploymentId !== 'string' || !build.deploymentId
            || typeof build.configUrl !== 'string' || typeof build.workerUrl !== 'string') {
            throw new TypeError(`The ${name} zkAPI build needs a deploymentId, configUrl and workerUrl.`);
        }
    }
    if (builds.legacy.deploymentId === builds.current.deploymentId) {
        throw new TypeError('The legacy and current zkAPI builds must serve different deployments.');
    }
}

/**
 * Choose a build from readBrowserWalletHoldings() output
 * ([{ deploymentId, runtime, withdrawals }]). Returns { build: 'legacy' |
 * 'current', reason, legacyOpen } where legacyOpen lists the legacy
 * deployment's open withdrawals (a set-aside close or a pending escape):
 * only the legacy build can finish them, so a host offers
 * { prefer: 'legacy' } for them. That is refused while this build's runtime
 * holds a note, because the legacy runtime cannot load over it.
 */
export function chooseZkapiBuild(holdings, builds, { prefer = null } = {}) {
    checkBuilds(builds);
    if (prefer != null && !['legacy', 'current'].includes(prefer)) throw new TypeError('prefer must be legacy or current.');
    const entries = Array.isArray(holdings) ? holdings : [];
    const slot = entries.find(entry => entry?.runtime === true) || null;
    const legacyOpen = entries.filter(entry => entry?.deploymentId === builds.legacy.deploymentId)
        .flatMap(entry => entry.withdrawals || []);
    if (slot?.deploymentId === builds.legacy.deploymentId) {
        return { build: 'legacy', reason: 'legacy_runtime_holds_note', legacyOpen };
    }
    if (prefer === 'legacy') {
        if (slot) {
            throw loaderError('legacy_build_blocked', `This browser's wallet holds a note of ${slot.deploymentId}; `
                + 'the legacy build cannot load until that note is closed.');
        }
        return { build: 'legacy', reason: 'requested', legacyOpen };
    }
    // A runtime of any other deployment (an older build): the current build's
    // reload() names it and refuses, which is the message the user needs.
    const reason = !slot ? 'no_runtime_note'
        : slot.deploymentId === builds.current.deploymentId ? 'current_runtime_holds_note' : 'other_deployment_runtime';
    return { build: 'current', reason, legacyOpen };
}

/**
 * Read the holdings, import() the chosen package entry and point it at its own
 * assets. Returns { build, reason, legacyOpen, deployment, sdk }; the host
 * then calls sdk.zkapiClient.init().
 */
export async function loadZkapi(builds, { readHoldings, importBuild, prefer = null } = {}) {
    if (typeof readHoldings !== 'function' || typeof importBuild !== 'function') {
        throw new TypeError('loadZkapi needs readHoldings and importBuild functions.');
    }
    const choice = chooseZkapiBuild(await readHoldings(), builds, { prefer });
    const deployment = builds[choice.build];
    const sdk = await importBuild(choice.build);
    sdk.configureBrowserSdk({ configUrl: deployment.configUrl, workerUrl: deployment.workerUrl });
    return { ...choice, deployment, sdk };
}
