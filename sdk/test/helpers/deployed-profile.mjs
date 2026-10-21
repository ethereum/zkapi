import { readFileSync } from 'node:fs';

/**
 * The shipped network profile filled in as a deployed vault of this SDK's
 * circuit and setup. The shipped profiles are `not_deployed` placeholders, so
 * tests that need a deployment take its pins from here.
 */
export function deployedProfile(network = 'sepolia', changes = {}) {
    const config = JSON.parse(readFileSync(new URL(`../../assets/config/${network}.json`, import.meta.url), 'utf8'));
    const { deployment_status: _placeholder, ...trusted } = config.trusted_deployment;
    return {
        ...config,
        deployment_manifest_url: 'https://protocol.example/config.json',
        allowed_deployment_manifest_urls: ['https://protocol.example/config.json'],
        trusted_deployment: {
            ...trusted,
            deployment_id: `zkapi-test-${network}-concession`,
            contract_address: `0x${'22'.repeat(20)}`,
            deploy_block: 1,
            protocol_server_url: 'https://protocol.example',
            indexer_url: 'https://protocol.example',
            state_signing_key: {
                x: '0x25a4453190e930f9716eebcab165170706d31d1b3969d106a50d7ae374a23d61',
                y: '0x1b0f74306dfce1371752a0d7c7d27359c398b8305798492fd1095074c0639953'
            },
            clearance_signing_key: {
                x: '0x2b8dc190013bb10de72398ca462027f21b7a35eb6cb957b9319d76bd3c3c1b7d',
                y: '0xa6744dc1bc99bf78b29d6e76db2a0b5598c79d1ce2377b9044aa9dc323dd963'
            },
            verifier_url: 'https://verifier.example',
            ...changes
        }
    };
}
