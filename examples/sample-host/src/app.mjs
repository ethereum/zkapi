// The host's entry. Both package entries are only reached through import(), so
// the bundler emits each SDK as its own chunk and a page fetches one of them.
// Holdings are read with the current package's store: both builds read the
// same database schema (version 3).
import { readBrowserWalletHoldings } from 'zkapi-sdk/store';
import { loadZkapi } from './loader.mjs';

/* global __ZKAPI_BUILDS__ */
/** { legacy, current }: { deploymentId, circuitId, publicPath, configUrl, workerUrl }, fixed by build.mjs. */
export const ZKAPI_BUILDS = Object.freeze(__ZKAPI_BUILDS__);

export function importZkapiBuild(build) {
    return build === 'legacy' ? import('zkapi-sdk-legacy') : import('zkapi-sdk');
}

/** Load the build this browser's wallet needs ({ prefer: 'legacy' } to finish a legacy withdrawal). */
export function startZkapi({ prefer = null } = {}) {
    return loadZkapi(ZKAPI_BUILDS, { readHoldings: readBrowserWalletHoldings, importBuild: importZkapiBuild, prefer });
}
