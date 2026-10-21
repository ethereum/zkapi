// Build one origin's static tree with both zkAPI browser builds (design §10.5):
//
//   <out>/zkapi/            the legacy note-bound build, at its existing publicPath
//   <out>/zkapi/v2c/        the concession build
//   <out>/app/              the host app; its loader import()s one SDK chunk
//   <out>/index.html
//   <out>/zkapi-builds.json the two deployments the loader tells apart
//
// Each package publishes its own keys, WebAssembly and worker through its own
// `./build` export, which refuses a profile it must not serve (the
// concession package refuses its `not_deployed` placeholder with
// deployment_not_deployed until its vault exists).
//
//   node build.mjs --out dist [--network sepolia]
import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const hostRoot = path.dirname(fileURLToPath(import.meta.url));

/** The two package entries (package.json dependencies) and where each is served. */
export const ZKAPI_PACKAGES = Object.freeze({
    legacy: Object.freeze({ name: 'zkapi-sdk-legacy', publicPath: '/zkapi/' }),
    current: Object.freeze({ name: 'zkapi-sdk', publicPath: '/zkapi/v2c/' })
});

function resolver(root) {
    const require = createRequire(path.join(root, 'package.json'));
    return specifier => pathToFileURL(require.resolve(specifier)).href;
}

/** Build both deployments' assets and the host app into outDir. */
export async function buildSampleHost({ outDir, network = 'sepolia', root = hostRoot } = {}) {
    if (!outDir) throw new TypeError('outDir is required.');
    const resolve = resolver(root);
    const esbuild = await import(resolve('esbuild'));
    const out = path.resolve(outDir);
    const builds = {};
    for (const [key, entry] of Object.entries(ZKAPI_PACKAGES)) {
        const { buildBrowserSdkAssets } = await import(resolve(`${entry.name}/build`));
        const result = await buildBrowserSdkAssets({
            outDir: path.join(out, ...entry.publicPath.split('/').filter(Boolean)),
            network,
            publicPath: entry.publicPath,
            build: esbuild.build
        });
        builds[key] = {
            deploymentId: result.config.trusted_deployment.deployment_id,
            circuitId: result.manifest.circuitId,
            publicPath: entry.publicPath,
            configUrl: result.configUrl,
            workerUrl: result.workerUrl
        };
    }
    await esbuild.build({
        absWorkingDir: root,
        entryPoints: [path.join(root, 'src/app.mjs')],
        outdir: path.join(out, 'app'),
        entryNames: 'app',
        chunkNames: 'chunks/[name]-[hash]',
        bundle: true,
        splitting: true,
        format: 'esm',
        platform: 'browser',
        target: ['es2022'],
        define: { __ZKAPI_BUILDS__: JSON.stringify(builds) },
        logLevel: 'warning'
    });
    await fs.copyFile(path.join(root, 'src/index.html'), path.join(out, 'index.html'));
    await fs.writeFile(path.join(out, 'zkapi-builds.json'), `${JSON.stringify(builds, null, 2)}\n`);
    return { directory: out, builds };
}

function option(args, name) {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : null;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
    const args = process.argv.slice(2);
    try {
        const { directory, builds } = await buildSampleHost({
            outDir: option(args, '--out') || 'dist',
            network: option(args, '--network') || 'sepolia'
        });
        for (const [key, build] of Object.entries(builds)) {
            console.log(`${key}: ${build.deploymentId} (${build.circuitId}) at ${build.publicPath}`);
        }
        console.log(`Built the sample host: ${directory}`);
    } catch (error) {
        console.error(error.code ? `${error.code}: ${error.message}` : error.message);
        process.exitCode = 1;
    }
}
