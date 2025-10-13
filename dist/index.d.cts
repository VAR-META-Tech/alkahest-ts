import * as viem from 'viem';
import { Hex, BlockNumber, BlockTag, WalletClient, Transport, Chain, Account, PublicActions } from 'viem';
import * as abitype from 'abitype';
import * as arktype from 'arktype';
import * as zod from 'zod';

type ChainAddresses = {
    eas: `0x${string}`;
    easSchemaRegistry: `0x${string}`;
    erc20EscrowObligation: `0x${string}`;
    erc20PaymentObligation: `0x${string}`;
    erc20BarterUtils: `0x${string}`;
    erc721EscrowObligation: `0x${string}`;
    erc721PaymentObligation: `0x${string}`;
    erc721BarterUtils: `0x${string}`;
    erc1155EscrowObligation: `0x${string}`;
    erc1155BarterUtils: `0x${string}`;
    erc1155PaymentObligation: `0x${string}`;
    tokenBundleEscrowObligation: `0x${string}`;
    tokenBundlePaymentObligation: `0x${string}`;
    tokenBundleBarterUtils: `0x${string}`;
    attestationEscrowObligation: `0x${string}`;
    attestationEscrowObligation2: `0x${string}`;
    attestationBarterUtils: `0x${string}`;
    stringObligation: `0x${string}`;
    trustedPartyArbiter: `0x${string}`;
    trivialArbiter: `0x${string}`;
    specificAttestationArbiter: `0x${string}`;
    trustedOracleArbiter: `0x${string}`;
    anyArbiter: `0x${string}`;
    allArbiter: `0x${string}`;
    intrinsicsArbiter: `0x${string}`;
    intrinsicsArbiter2: `0x${string}`;
    attesterArbiterComposing?: `0x${string}`;
    expirationTimeArbiterComposing?: `0x${string}`;
    recipientArbiterComposing?: `0x${string}`;
    refUidArbiterComposing?: `0x${string}`;
    revocableArbiterComposing?: `0x${string}`;
    revocationTimeArbiterComposing?: `0x${string}`;
    schemaArbiterComposing?: `0x${string}`;
    timestampArbiterComposing?: `0x${string}`;
    uidArbiterComposing?: `0x${string}`;
    valueArbiterComposing?: `0x${string}`;
    attesterArbiterNonComposing?: `0x${string}`;
    expirationTimeArbiterNonComposing?: `0x${string}`;
    recipientArbiterNonComposing?: `0x${string}`;
    refUidArbiterNonComposing?: `0x${string}`;
    revocableArbiterNonComposing?: `0x${string}`;
    revocationTimeArbiterNonComposing?: `0x${string}`;
    schemaArbiterNonComposing?: `0x${string}`;
    timestampArbiterNonComposing?: `0x${string}`;
    uidArbiterNonComposing?: `0x${string}`;
    valueArbiterNonComposing?: `0x${string}`;
};
type PermitSignature = {
    deadline: bigint;
    v: number;
    r: `0x${string}`;
    s: `0x${string}`;
};
type SignPermitProps = {
    /** Address of the token to approve */
    contractAddress: Hex;
    /** Name of the token to approve.
     * Corresponds to the `name` method on the ERC-20 contract. Please note this must match exactly byte-for-byte */
    erc20Name: string;
    /** Owner of the tokens. Usually the currently connected address. */
    ownerAddress: Hex;
    /** Address to grant allowance to */
    spenderAddress: Hex;
    /** Expiration of this approval, in SECONDS */
    deadline: bigint;
    /** Numerical chainId of the token contract */
    chainId: number;
    /** Defaults to 1. Some tokens need a different version, check the [PERMIT INFORMATION](https://github.com/vacekj/wagmi-permit/blob/main/PERMIT.md) for more information */
    permitVersion?: string;
    /** Permit nonce for the specific address and token contract. You can get the nonce from the `nonces` method on the token contract. */
    nonce: bigint;
};
type Eip2612Props = SignPermitProps & {
    /** Amount to approve */
    value: bigint;
};
type Erc20 = {
    address: `0x${string}`;
    value: bigint;
};
type Erc721 = {
    address: `0x${string}`;
    id: bigint;
};
type Erc1155 = {
    address: `0x${string}`;
    id: bigint;
    value: bigint;
};
type Demand = {
    arbiter: `0x${string}`;
    demand: `0x${string}`;
};
type TokenBundle = {
    erc20s: Erc20[];
    erc721s: Erc721[];
    erc1155s: Erc1155[];
};
type TokenBundleFlat = {
    erc20Tokens: `0x${string}`[];
    erc20Amounts: bigint[];
    erc721Tokens: `0x${string}`[];
    erc721TokenIds: bigint[];
    erc1155Tokens: `0x${string}`[];
    erc1155TokenIds: bigint[];
    erc1155Amounts: bigint[];
};
type ApprovalPurpose = "escrow" | "payment";
type Attestation = {
    uid: `0x${string}`;
    schema: `0x${string}`;
    time: bigint;
    expirationTime: bigint;
    revocationTime: bigint;
    refUID: `0x${string}`;
    recipient: `0x${string}`;
    attester: `0x${string}`;
    revocable: boolean;
    data: `0x${string}`;
};
interface TimeFilters {
    /** Only process attestations after this timestamp (Unix timestamp in seconds) */
    minTime?: bigint;
    /** Only process attestations before this timestamp (Unix timestamp in seconds) */
    maxTime?: bigint;
    /** Skip attestations past their expiration time */
    excludeExpired?: boolean;
    /** Only process attestations older than this duration (seconds) */
    minAge?: bigint;
    /** Only process attestations newer than this duration (seconds) */
    maxAge?: bigint;
}
interface AttestationFilters {
    /** Only process attestations from specific attester */
    specificAttester?: string;
    /** Skip attestations from these attesters */
    excludeAttesters?: string[];
    /** Only process attestations for specific recipient */
    specificRecipient?: string;
    /** Skip revoked attestations */
    excludeRevoked?: boolean;
    /** Only process attestations with reference UID */
    requireRefUID?: boolean;
    /** Only process attestations with specific schema */
    specificSchema?: string;
}
interface BlockFilters {
    /** Start from specific block number or block tag */
    fromBlock?: BlockNumber | BlockTag;
    /** End at specific block number or block tag */
    toBlock?: BlockNumber | BlockTag;
    /** Limit the block range to prevent timeouts */
    maxBlockRange?: bigint;
}
interface BatchFilters {
    /** Limit number of obligations to process */
    maxObligations?: number;
    /** Process recent attestations first */
    prioritizeRecent?: boolean;
    /** Process in batches of this size */
    batchSize?: number;
}
interface PerformanceFilters {
    /** Skip if estimated gas exceeds limit */
    maxGasPerTx?: bigint;
    /** Only simulate, don't execute transactions */
    dryRun?: boolean;
    /** Skip validation for faster processing */
    skipValidation?: boolean;
}
interface EnhancedArbitrateFilters extends TimeFilters, AttestationFilters, BlockFilters, BatchFilters, PerformanceFilters {
    /** Only arbitrate if escrow demands current oracle */
    onlyIfEscrowDemandsCurrentOracle?: boolean;
    /** Skip obligations that have already been arbitrated */
    skipAlreadyArbitrated?: boolean;
}

declare const contractAddresses: Record<string, ChainAddresses>;
declare const supportedChains: string[];

declare function makeExtendableClient<T extends object>(base: T): T & {
    extend<U extends object>(extender: (client: T) => U): T & U;
};
/**
 * Creates the default extension for the Alkahest client with all standard functionality
 * @param client - The base client to extend
 * @returns Extension object with all standard client functionality
 */
declare const makeDefaultExtension: (client: any) => {
    /** Unified client for all arbiter functionality */
    arbiters: {
        encodeMultiArbiterDemand: (demand: {
            arbiters: `0x${string}`[];
            demands: `0x${string}`[];
        }) => `0x${string}`;
        decodeMultiArbiterDemand: (demandData: `0x${string}`) => {
            arbiters: readonly `0x${string}`[];
            demands: readonly `0x${string}`[];
        };
        encodeAttesterArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            attester: `0x${string}`;
        }) => `0x${string}`;
        decodeAttesterArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeAttesterArbiterNonComposingDemand: (demand: {
            attester: `0x${string}`;
        }) => `0x${string}`;
        decodeAttesterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeAfterArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            time: bigint;
        }) => `0x${string}`;
        decodeTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeAfterArbiterNonComposingDemand: (demand: {
            time: bigint;
        }) => `0x${string}`;
        decodeTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeBeforeArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            time: bigint;
        }) => `0x${string}`;
        decodeTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeBeforeArbiterNonComposingDemand: (demand: {
            time: bigint;
        }) => `0x${string}`;
        decodeTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeEqualArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            time: bigint;
        }) => `0x${string}`;
        decodeTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeTimeEqualArbiterNonComposingDemand: (demand: {
            time: bigint;
        }) => `0x${string}`;
        decodeTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeAfterArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeAfterArbiterNonComposingDemand: (demand: {
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeBeforeArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeBeforeArbiterNonComposingDemand: (demand: {
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeEqualArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeExpirationTimeEqualArbiterNonComposingDemand: (demand: {
            expirationTime: bigint;
        }) => `0x${string}`;
        decodeExpirationTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeRecipientArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            recipient: `0x${string}`;
        }) => `0x${string}`;
        decodeRecipientArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeRecipientArbiterNonComposingDemand: (demand: {
            recipient: `0x${string}`;
        }) => `0x${string}`;
        decodeRecipientArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeRefUidArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            refUID: `0x${string}`;
        }) => `0x${string}`;
        decodeRefUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeRefUidArbiterNonComposingDemand: (demand: {
            refUID: `0x${string}`;
        }) => `0x${string}`;
        decodeRefUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeRevocableArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            revocable: boolean;
        }) => `0x${string}`;
        decodeRevocableArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeRevocableArbiterNonComposingDemand: (demand: {
            revocable: boolean;
        }) => `0x${string}`;
        decodeRevocableArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeSchemaArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            schema: `0x${string}`;
        }) => `0x${string}`;
        decodeSchemaArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeSchemaArbiterNonComposingDemand: (demand: {
            schema: `0x${string}`;
        }) => `0x${string}`;
        decodeSchemaArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeUidArbiterComposingDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            uid: `0x${string}`;
        }) => `0x${string}`;
        decodeUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
        encodeUidArbiterNonComposingDemand: (demand: {
            uid: `0x${string}`;
        }) => `0x${string}`;
        decodeUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
        encodeAnyArbiterDemand: (demand: {
            arbiters: `0x${string}`[];
            demands: `0x${string}`[];
        }) => `0x${string}`;
        decodeAnyArbiterDemand: (demandData: `0x${string}`) => {
            arbiters: readonly `0x${string}`[];
            demands: readonly `0x${string}`[];
        };
        encodeAllArbiterDemand: (demand: {
            arbiters: `0x${string}`[];
            demands: `0x${string}`[];
        }) => `0x${string}`;
        decodeAllArbiterDemand: (demandData: `0x${string}`) => {
            arbiters: readonly `0x${string}`[];
            demands: readonly `0x${string}`[];
        };
        encodeIntrinsics2Demand: (demand: {
            schema: `0x${string}`;
        }) => `0x${string}`;
        decodeIntrinsics2Demand: (demandData: `0x${string}`) => {
            schema: `0x${string}`;
        };
        encodeTrustedPartyDemand: (demand: {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            creator: `0x${string}`;
        }) => `0x${string}`;
        decodeTrustedPartyDemand: (demandData: `0x${string}`) => {
            baseArbiter: `0x${string}`;
            baseDemand: `0x${string}`;
            creator: `0x${string}`;
        };
        encodeSpecificAttestationDemand: (demand: {
            uid: `0x${string}`;
        }) => `0x${string}`;
        decodeSpecificAttestationDemand: (demandData: `0x${string}`) => {
            uid: `0x${string}`;
        };
        encodeTrustedOracleDemand: (demand: {
            oracle: `0x${string}`;
            data: `0x${string}`;
        }) => `0x${string}`;
        decodeTrustedOracleDemand: (demandData: `0x${string}`) => {
            oracle: `0x${string}`;
            data: `0x${string}`;
        };
        arbitrateAsTrustedOracle: (obligation: `0x${string}`, decision: boolean) => Promise<`0x${string}`>;
        requestArbitrationFromTrustedOracle: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<`0x${string}`>;
        checkExistingArbitration: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<{
            obligation: `0x${string}`;
            oracle: `0x${string}`;
            decision: boolean;
        } | undefined>;
        waitForTrustedOracleArbitration: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
            obligation?: `0x${string}` | undefined;
            oracle?: `0x${string}` | undefined;
            decision?: boolean | undefined;
        }>;
        waitForTrustedOracleArbitrationRequest: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
            obligation?: `0x${string}` | undefined;
            oracle?: `0x${string}` | undefined;
        }>;
        listenForArbitrationRequestsOnly: (oracle: `0x${string}`, arbitrationHandler: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<boolean>, pollingInterval?: number) => viem.WatchEventReturnType;
    };
    /** Methods for interacting with ERC20 tokens */
    erc20: {
        encodeEscrowObligationRaw: (data: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            amount: bigint;
        }) => `0x${string}`;
        encodePaymentObligationRaw: (data: {
            token: `0x${string}`;
            amount: bigint;
            payee: `0x${string}`;
        }) => `0x${string}`;
        encodeEscrowObligation: (token: Erc20, demand: Demand) => `0x${string}`;
        encodePaymentObligation: (token: Erc20, payee: `0x${string}`) => `0x${string}`;
        decodeEscrowObligation: (obligationData: `0x${string}`) => any;
        decodePaymentObligation: (obligationData: `0x${string}`) => any;
        getEscrowSchema: () => Promise<`0x${string}`>;
        getPaymentSchema: () => Promise<`0x${string}`>;
        getEscrowObligation: (uid: `0x${string}`) => Promise<{
            data: any;
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
        getPaymentObligation: (uid: `0x${string}`) => Promise<{
            data: any;
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
        approve: (token: Erc20, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        approveIfLess: (token: Erc20, purpose: ApprovalPurpose) => Promise<`0x${string}` | null>;
        collectEscrow: (buyAttestation: `0x${string}`, fulfillment: `0x${string}`) => Promise<`0x${string}`>;
        reclaimExpired: (buyAttestation: `0x${string}`) => Promise<`0x${string}`>;
        buyWithErc20: (price: Erc20, item: Demand, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndBuyWithErc20: (price: Erc20, item: Demand, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payWithErc20: (price: Erc20, payee: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndPayWithErc20: (price: Erc20, payee: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc20ForErc20: (bid: Erc20, ask: Erc20, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndBuyErc20ForErc20: (bid: Erc20, ask: Erc20, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc20ForErc20: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndPayErc20ForErc20: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc721WithErc20: (bid: Erc20, ask: Erc721, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndBuyErc721WithErc20: (bid: Erc20, ask: Erc721, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc20ForErc721: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndPayErc20ForErc721: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc1155WithErc20: (bid: Erc20, ask: Erc1155, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndBuyErc1155WithErc20: (bid: Erc20, ask: Erc1155, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc20ForErc1155: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndPayErc20ForErc1155: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyBundleWithErc20: (bid: Erc20, bundle: TokenBundle, payee: `0x${string}`, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndBuyBundleWithErc20: (bid: Erc20, bundle: TokenBundle, payee: `0x${string}`, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc20ForBundle: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        permitAndPayErc20ForBundle: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
    };
    /** Methods for interacting with ERC721 tokens */
    erc721: {
        encodeEscrowObligationRaw: (data: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            tokenId: bigint;
        }) => `0x${string}`;
        encodePaymentObligationRaw: (data: {
            token: `0x${string}`;
            tokenId: bigint;
            payee: `0x${string}`;
        }) => `0x${string}`;
        encodeEscrowObligation: (token: Erc721, demand: Demand) => `0x${string}`;
        encodePaymentObligation: (token: Erc721, payee: `0x${string}`) => `0x${string}`;
        decodeEscrowObligation: (obligationData: `0x${string}`) => any;
        decodePaymentObligation: (obligationData: `0x${string}`) => any;
        approve: (token: Erc721, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        approveAll: (token_contract: `0x${string}`, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        revokeAll: (token_contract: `0x${string}`, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        collectEscrow: (buyAttestation: `0x${string}`, fulfillment: `0x${string}`) => Promise<`0x${string}`>;
        reclaimExpired: (buyAttestation: `0x${string}`) => Promise<`0x${string}`>;
        buyWithErc721: (price: Erc721, item: Demand, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payWithErc721: (price: Erc721, payee: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc721ForErc721: (bid: Erc721, ask: Erc721, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc721ForErc721: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
        }>;
        buyErc20WithErc721: (bid: Erc721, ask: Erc20, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc721ForErc20: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc1155WithErc721: (bid: Erc721, ask: Erc1155, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc721ForErc1155: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyBundleWithErc721: (bid: Erc721, ask: TokenBundle, payee: `0x${string}`, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc721ForBundle: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
    };
    /** Methods for interacting with ERC1155 tokens */
    erc1155: {
        encodeEscrowObligationRaw: (data: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            tokenId: bigint;
            amount: bigint;
        }) => `0x${string}`;
        encodePaymentObligationRaw: (data: {
            token: `0x${string}`;
            tokenId: bigint;
            amount: bigint;
            payee: `0x${string}`;
        }) => `0x${string}`;
        encodeEscrowObligation: (token: Erc1155, demand: Demand) => `0x${string}`;
        encodePaymentObligation: (token: Erc1155, payee: `0x${string}`) => `0x${string}`;
        decodeEscrowObligation: (obligationData: `0x${string}`) => any;
        decodePaymentObligation: (obligationData: `0x${string}`) => any;
        approveAll: (token_contract: `0x${string}`, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        revokeAll: (token_contract: `0x${string}`, purpose: ApprovalPurpose) => Promise<`0x${string}`>;
        collectEscrow: (buyAttestation: `0x${string}`, fulfillment: `0x${string}`) => Promise<`0x${string}`>;
        reclaimExpired: (buyAttestation: `0x${string}`) => Promise<`0x${string}`>;
        buyWithErc1155: (price: Erc1155, item: Demand, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payWithErc1155: (price: Erc1155, payee: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc1155ForErc1155: (bid: Erc1155, ask: Erc1155, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc1155ForErc1155: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
        }>;
        buyErc20WithErc1155: (bid: Erc1155, ask: Erc20, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc1155ForErc20: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyErc721WithErc1155: (bid: Erc1155, ask: Erc721, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc1155ForErc721: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyBundleWithErc1155: (bid: Erc1155, ask: TokenBundle, payee: `0x${string}`, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payErc1155ForBundle: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
    };
    /** Methods for interacting with token bundles */
    bundle: {
        encodeEscrowObligationRaw: (data: {
            erc20Tokens: `0x${string}`[];
            erc20Amounts: bigint[];
            erc721Tokens: `0x${string}`[];
            erc721TokenIds: bigint[];
            erc1155Tokens: `0x${string}`[];
            erc1155TokenIds: bigint[];
            erc1155Amounts: bigint[];
            arbiter: `0x${string}`;
            demand: `0x${string}`;
        }) => `0x${string}`;
        encodePaymentObligationRaw: (data: {
            erc20Tokens: `0x${string}`[];
            erc20Amounts: bigint[];
            erc721Tokens: `0x${string}`[];
            erc721TokenIds: bigint[];
            erc1155Tokens: `0x${string}`[];
            erc1155TokenIds: bigint[];
            erc1155Amounts: bigint[];
            payee: `0x${string}`;
        }) => `0x${string}`;
        encodeEscrowObligation: (bundle: TokenBundle, demand: Demand) => `0x${string}`;
        encodePaymentObligation: (bundle: TokenBundle, payee: `0x${string}`) => `0x${string}`;
        decodeEscrowObligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            erc20Tokens: readonly `0x${string}`[];
            erc20Amounts: readonly bigint[];
            erc721Tokens: readonly `0x${string}`[];
            erc721TokenIds: readonly bigint[];
            erc1155Tokens: readonly `0x${string}`[];
            erc1155TokenIds: readonly bigint[];
            erc1155Amounts: readonly bigint[];
        };
        decodePaymentObligation: (obligationData: `0x${string}`) => {
            erc20Tokens: readonly `0x${string}`[];
            erc20Amounts: readonly bigint[];
            erc721Tokens: readonly `0x${string}`[];
            erc721TokenIds: readonly bigint[];
            erc1155Tokens: readonly `0x${string}`[];
            erc1155TokenIds: readonly bigint[];
            erc1155Amounts: readonly bigint[];
            payee: `0x${string}`;
        };
        collectEscrow: (buyAttestation: `0x${string}`, fulfillment: `0x${string}`) => Promise<`0x${string}`>;
        reclaimExpired: (buyAttestation: `0x${string}`) => Promise<`0x${string}`>;
        buyWithBundle: (price: TokenBundle, item: Demand, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payWithBundle: (price: TokenBundle, payee: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyBundleForBundle: (bid: TokenBundle, ask: TokenBundle, expiration: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        payBundleForBundle: (buyAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        approve: (bundle: TokenBundle, purpose: ApprovalPurpose) => Promise<`0x${string}`[]>;
    };
    /** Methods for interacting with attestations */
    attestation: {
        encodeEscrowObligation: (data: {
            attestation: {
                schema: `0x${string}`;
                data: {
                    recipient: `0x${string}`;
                    expirationTime: bigint;
                    revocable: boolean;
                    refUID: `0x${string}`;
                    data: `0x${string}`;
                    value: bigint;
                };
            };
            arbiter: `0x${string}`;
            demand: `0x${string}`;
        }) => `0x${string}`;
        encodeEscrow2Obligation: (data: {
            attestationUid: `0x${string}`;
            arbiter: `0x${string}`;
            demand: `0x${string}`;
        }) => `0x${string}`;
        decodeEscrowObligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            attestation: {
                schema: `0x${string}`;
                data: {
                    recipient: `0x${string}`;
                    expirationTime: bigint;
                    revocable: boolean;
                    refUID: `0x${string}`;
                    data: `0x${string}`;
                    value: bigint;
                };
            };
        };
        decodeEscrow2Obligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            attestationUid: `0x${string}`;
        };
        getEscrowSchema: () => Promise<`0x${string}`>;
        getEscrow2Schema: () => Promise<`0x${string}`>;
        getEscrowObligation: (uid: `0x${string}`) => Promise<{
            data: {
                arbiter: `0x${string}`;
                demand: `0x${string}`;
                attestation: {
                    schema: `0x${string}`;
                    data: {
                        recipient: `0x${string}`;
                        expirationTime: bigint;
                        revocable: boolean;
                        refUID: `0x${string}`;
                        data: `0x${string}`;
                        value: bigint;
                    };
                };
            };
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
        getEscrow2Obligation: (uid: `0x${string}`) => Promise<{
            data: {
                arbiter: `0x${string}`;
                demand: `0x${string}`;
                attestationUid: `0x${string}`;
            };
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
        buyWithAttestation: (attestation: {
            schema: `0x${string}`;
            data: {
                recipient: `0x${string}`;
                expirationTime: bigint;
                revocable: boolean;
                refUID: `0x${string}`;
                data: `0x${string}`;
                value: bigint;
            };
        }, item: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
        }, expiration?: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        collectEscrow: (escrowAttestation: `0x${string}`, fulfillmentAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        buyWithAttestation2: (attestationUid: `0x${string}`, item: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
        }, expiration?: bigint) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        collectEscrow2: (escrowAttestation: `0x${string}`, fulfillmentAttestation: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        registerSchema: (schema: string, resolver: `0x${string}`, revocable: boolean) => Promise<`0x${string}`>;
        createAttestation: (schema: `0x${string}`, recipient: `0x${string}`, expirationTime: bigint, revocable: boolean, refUID: `0x${string}`, data: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        attestAndCreateEscrow: (attestation: {
            schema: `0x${string}`;
            data: {
                recipient: `0x${string}`;
                expirationTime: bigint;
                revocable: boolean;
                refUID: `0x${string}`;
                data: `0x${string}`;
                value: bigint;
            };
        }, escrow: {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            expirationTime: bigint;
        }) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
    };
    /** Utilities for StringObligation */
    stringObligation: {
        encode: (data: {
            item: string;
        }) => `0x${string}`;
        decode: (obligationData: `0x${string}`) => any;
        decodeJson: <T>(obligationData: `0x${string}`) => T;
        decodeZod: <TSchema extends zod.ZodType, TAsync extends boolean = false, TSafe extends boolean = false>(obligationData: `0x${string}`, schema: TSchema, schemaOptions?: Partial<zod.ParseParams>, parseOptions?: {
            async: TAsync;
            safe: TSafe;
        }) => TSafe extends true ? TAsync extends true ? Promise<zod.SafeParseReturnType<zod.TypeOf<TSchema>, zod.TypeOf<TSchema>>> : zod.SafeParseReturnType<zod.TypeOf<TSchema>, zod.TypeOf<TSchema>> : TAsync extends true ? Promise<zod.TypeOf<TSchema>> : zod.TypeOf<TSchema>;
        decodeArkType: <Schema extends arktype.Type<any, any>>(obligationData: `0x${string}`, schema: Schema) => Schema["inferOut"];
        doObligation: (item: string, refUID?: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        doObligationJson: <T>(item: T, refUid?: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        getSchema: () => Promise<`0x${string}`>;
        getObligation: (uid: `0x${string}`) => Promise<{
            data: any;
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
        getJsonObligation: <T>(uid: `0x${string}`) => Promise<{
            data: {
                item: T;
            };
            uid: `0x${string}`;
            schema: `0x${string}`;
            time: bigint;
            expirationTime: bigint;
            revocationTime: bigint;
            refUID: `0x${string}`;
            recipient: `0x${string}`;
            attester: `0x${string}`;
            revocable: boolean;
        }>;
    };
    oracle: {
        arbitratePast: <T extends readonly abitype.AbiParameter[]>(params: {
            fulfillment: {
                obligationAbi: T;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_3]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_1 ? { [key in keyof T_1]: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never) => Promise<boolean | null>;
        } & EnhancedArbitrateFilters) => Promise<{
            decisions: ({
                simulated: boolean;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_3]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_1 ? { [key in keyof T_1]: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                decision: boolean | null;
                estimatedGas: bigint | null;
                hash?: undefined;
            } | {
                hash: `0x${string}`;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_6 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_6]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_4 ? { [key in keyof T_4]: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_5]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                decision: boolean;
                simulated?: undefined;
                estimatedGas?: undefined;
            })[];
            fulfillments: {
                log: viem.Log<bigint, number, boolean, {
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }, undefined, [{
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }], "Attested">;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_9 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_9]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_7 ? { [key in keyof T_7]: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_8 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_8]: abitype.AbiParameterToPrimitiveType<(T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
            }[];
        }>;
        listenAndArbitrate: <ObligationData extends readonly abitype.AbiParameter[]>(params: {
            fulfillment: {
                obligationAbi: ObligationData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never) => Promise<boolean | null>;
        } & {
            onlyIfEscrowDemandsCurrentOracle?: boolean;
            skipAlreadyArbitrated?: boolean;
            onAfterArbitrate?: (decision: {
                hash: `0x${string}`;
                attestation: Attestation;
                obligation: viem.DecodeAbiParametersReturnType<ObligationData>;
                decision: boolean | null;
            }) => Promise<void>;
            pollingInterval?: number;
        }) => Promise<{
            decisions: {
                decisions: ({
                    simulated: boolean;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_6 ? T_6 extends ObligationData ? T_6 extends readonly abitype.AbiParameter[] ? T_6 : abitype.AbiParameter[] : never : never) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_5 ? T_5 extends ObligationData ? T_5 extends readonly abitype.AbiParameter[] ? T_5 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends infer T_3 ? T_3 extends ObligationData ? T_3 extends readonly abitype.AbiParameter[] ? T_3 : abitype.AbiParameter[] : never : never) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_2 ? T_2 extends ObligationData ? T_2 extends readonly abitype.AbiParameter[] ? T_2 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                    decision: boolean | null;
                    estimatedGas: bigint | null;
                    hash?: undefined;
                } | {
                    hash: `0x${string}`;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_13 ? T_13 extends ObligationData ? T_13 extends readonly abitype.AbiParameter[] ? T_13 : abitype.AbiParameter[] : never : never) extends infer T_11 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_11]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_12 ? T_12 extends ObligationData ? T_12 extends readonly abitype.AbiParameter[] ? T_12 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T_7 ? { [key in keyof T_7]: ((ObligationData extends infer T_10 ? T_10 extends ObligationData ? T_10 extends readonly abitype.AbiParameter[] ? T_10 : abitype.AbiParameter[] : never : never) extends infer T_8 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_8]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_9 ? T_9 extends ObligationData ? T_9 extends readonly abitype.AbiParameter[] ? T_9 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                    decision: boolean;
                    simulated?: undefined;
                    estimatedGas?: undefined;
                })[];
                fulfillments: {
                    log: viem.Log<bigint, number, boolean, {
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }, undefined, [{
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }], "Attested">;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_20 ? T_20 extends ObligationData ? T_20 extends readonly abitype.AbiParameter[] ? T_20 : abitype.AbiParameter[] : never : never) extends infer T_18 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_18]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_19 ? T_19 extends ObligationData ? T_19 extends readonly abitype.AbiParameter[] ? T_19 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T_14 ? { [key in keyof T_14]: ((ObligationData extends infer T_17 ? T_17 extends ObligationData ? T_17 extends readonly abitype.AbiParameter[] ? T_17 : abitype.AbiParameter[] : never : never) extends infer T_15 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_15]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_16 ? T_16 extends ObligationData ? T_16 extends readonly abitype.AbiParameter[] ? T_16 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                }[];
            };
            unwatch: viem.WatchEventReturnType;
        }>;
        listenAndArbitrateNewFulfillments: <ObligationData extends readonly abitype.AbiParameter[]>(params: {
            fulfillment: {
                obligationAbi: ObligationData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never) => Promise<boolean | null>;
        } & {
            onlyIfEscrowDemandsCurrentOracle?: boolean;
            skipAlreadyArbitrated?: boolean;
            onAfterArbitrate?: (decision: {
                hash: `0x${string}`;
                attestation: Attestation;
                obligation: viem.DecodeAbiParametersReturnType<ObligationData>;
                decision: boolean | null;
            }) => Promise<void>;
            pollingInterval?: number;
        }) => Promise<{
            unwatch: viem.WatchEventReturnType;
        }>;
        arbitratePastForEscrow: <ObligationData extends readonly abitype.AbiParameter[], DemandData extends readonly abitype.AbiParameter[]>(params: {
            escrow: {
                demandAbi: DemandData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            fulfillment: {
                obligationAbi: ObligationData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_5]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_3 ? { [key_2 in keyof T_3]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never) => Promise<boolean | null>;
        } & EnhancedArbitrateFilters) => Promise<{
            decisions: ({
                simulated: boolean;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_5]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_3 ? { [key_2 in keyof T_3]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
                escrowAttestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                decision: boolean | null;
                estimatedGas: bigint | null;
                hash?: undefined;
            } | {
                hash: `0x${string}`;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_8 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_8]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_6 ? { [key in keyof T_6]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_7 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_7]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_11 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_11]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_9 ? { [key_2 in keyof T_9]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_10 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_10]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
                escrowAttestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                decision: boolean;
                simulated?: undefined;
                estimatedGas?: undefined;
            })[];
            escrows: {
                log: viem.Log<bigint, number, boolean, {
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }, undefined, [{
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }], "Attested">;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: readonly [{
                    arbiter: `0x${string}`;
                    demand: `0x${string}`;
                }];
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_14 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_14]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_12 ? { [key_2 in keyof T_12]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_13 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_13]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
            }[];
            fulfillments: {
                log: viem.Log<bigint, number, boolean, {
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }, undefined, [{
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }], "Attested">;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_17 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_17]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T_15 ? { [key in keyof T_15]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_16 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_16]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
            }[];
        }>;
        listenAndArbitrateForEscrow: <ObligationData extends readonly abitype.AbiParameter[], DemandData extends readonly abitype.AbiParameter[]>(params: {
            escrow: {
                demandAbi: DemandData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            fulfillment: {
                obligationAbi: ObligationData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_5]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_3 ? { [key_2 in keyof T_3]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never) => Promise<boolean | null>;
        } & {
            skipAlreadyArbitrated?: boolean;
            onAfterArbitrate?: (decision: {
                hash: `0x${string}`;
                attestation: Attestation;
                obligation: viem.DecodeAbiParametersReturnType<ObligationData>;
                demand: viem.DecodeAbiParametersReturnType<DemandData>;
                escrowAttestation: Attestation;
                decision: boolean | null;
            }) => Promise<void>;
            pollingInterval?: number;
        }) => Promise<{
            decisions: {
                decisions: ({
                    simulated: boolean;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_6 ? T_6 extends ObligationData ? T_6 extends readonly abitype.AbiParameter[] ? T_6 : abitype.AbiParameter[] : never : never) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_5 ? T_5 extends ObligationData ? T_5 extends readonly abitype.AbiParameter[] ? T_5 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends infer T_3 ? T_3 extends ObligationData ? T_3 extends readonly abitype.AbiParameter[] ? T_3 : abitype.AbiParameter[] : never : never) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_2 ? T_2 extends ObligationData ? T_2 extends readonly abitype.AbiParameter[] ? T_2 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                    demand: ((DemandData extends infer T_13 ? T_13 extends DemandData ? T_13 extends readonly abitype.AbiParameter[] ? T_13 : abitype.AbiParameter[] : never : never) extends infer T_11 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_11]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_12 ? T_12 extends DemandData ? T_12 extends readonly abitype.AbiParameter[] ? T_12 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never) extends infer T_7 ? { [key_2 in keyof T_7]: ((DemandData extends infer T_10 ? T_10 extends DemandData ? T_10 extends readonly abitype.AbiParameter[] ? T_10 : abitype.AbiParameter[] : never : never) extends infer T_8 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_8]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_9 ? T_9 extends DemandData ? T_9 extends readonly abitype.AbiParameter[] ? T_9 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
                    escrowAttestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    decision: boolean | null;
                    estimatedGas: bigint | null;
                    hash?: undefined;
                } | {
                    hash: `0x${string}`;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_20 ? T_20 extends ObligationData ? T_20 extends readonly abitype.AbiParameter[] ? T_20 : abitype.AbiParameter[] : never : never) extends infer T_18 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_18]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_19 ? T_19 extends ObligationData ? T_19 extends readonly abitype.AbiParameter[] ? T_19 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T_14 ? { [key in keyof T_14]: ((ObligationData extends infer T_17 ? T_17 extends ObligationData ? T_17 extends readonly abitype.AbiParameter[] ? T_17 : abitype.AbiParameter[] : never : never) extends infer T_15 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_15]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_16 ? T_16 extends ObligationData ? T_16 extends readonly abitype.AbiParameter[] ? T_16 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                    demand: ((DemandData extends infer T_27 ? T_27 extends DemandData ? T_27 extends readonly abitype.AbiParameter[] ? T_27 : abitype.AbiParameter[] : never : never) extends infer T_25 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_25]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_26 ? T_26 extends DemandData ? T_26 extends readonly abitype.AbiParameter[] ? T_26 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never) extends infer T_21 ? { [key_2 in keyof T_21]: ((DemandData extends infer T_24 ? T_24 extends DemandData ? T_24 extends readonly abitype.AbiParameter[] ? T_24 : abitype.AbiParameter[] : never : never) extends infer T_22 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_22]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_23 ? T_23 extends DemandData ? T_23 extends readonly abitype.AbiParameter[] ? T_23 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
                    escrowAttestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    decision: boolean;
                    simulated?: undefined;
                    estimatedGas?: undefined;
                })[];
                escrows: {
                    log: viem.Log<bigint, number, boolean, {
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }, undefined, [{
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }], "Attested">;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: readonly [{
                        arbiter: `0x${string}`;
                        demand: `0x${string}`;
                    }];
                    demand: ((DemandData extends infer T_34 ? T_34 extends DemandData ? T_34 extends readonly abitype.AbiParameter[] ? T_34 : abitype.AbiParameter[] : never : never) extends infer T_32 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_32]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_33 ? T_33 extends DemandData ? T_33 extends readonly abitype.AbiParameter[] ? T_33 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never) extends infer T_28 ? { [key_2 in keyof T_28]: ((DemandData extends infer T_31 ? T_31 extends DemandData ? T_31 extends readonly abitype.AbiParameter[] ? T_31 : abitype.AbiParameter[] : never : never) extends infer T_29 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_29]: abitype.AbiParameterToPrimitiveType<(DemandData extends infer T_30 ? T_30 extends DemandData ? T_30 extends readonly abitype.AbiParameter[] ? T_30 : abitype.AbiParameter[] : never : never)[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never;
                }[];
                fulfillments: {
                    log: viem.Log<bigint, number, boolean, {
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }, undefined, [{
                        readonly name: "Attested";
                        readonly type: "event";
                        readonly inputs: readonly [{
                            readonly type: "address";
                            readonly name: "recipient";
                            readonly indexed: true;
                        }, {
                            readonly type: "address";
                            readonly name: "attester";
                            readonly indexed: true;
                        }, {
                            readonly type: "bytes32";
                            readonly name: "uid";
                        }, {
                            readonly type: "bytes32";
                            readonly name: "schemaUID";
                            readonly indexed: true;
                        }];
                    }], "Attested">;
                    attestation: {
                        uid: `0x${string}`;
                        schema: `0x${string}`;
                        time: bigint;
                        expirationTime: bigint;
                        revocationTime: bigint;
                        refUID: `0x${string}`;
                        recipient: `0x${string}`;
                        attester: `0x${string}`;
                        revocable: boolean;
                        data: `0x${string}`;
                    };
                    obligation: ((ObligationData extends infer T_41 ? T_41 extends ObligationData ? T_41 extends readonly abitype.AbiParameter[] ? T_41 : abitype.AbiParameter[] : never : never) extends infer T_39 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_39]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_40 ? T_40 extends ObligationData ? T_40 extends readonly abitype.AbiParameter[] ? T_40 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never) extends infer T_35 ? { [key in keyof T_35]: ((ObligationData extends infer T_38 ? T_38 extends ObligationData ? T_38 extends readonly abitype.AbiParameter[] ? T_38 : abitype.AbiParameter[] : never : never) extends infer T_36 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_36]: abitype.AbiParameterToPrimitiveType<(ObligationData extends infer T_37 ? T_37 extends ObligationData ? T_37 extends readonly abitype.AbiParameter[] ? T_37 : abitype.AbiParameter[] : never : never)[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
                }[];
            };
            unwatch: () => void;
        }>;
        listenAndArbitrateNewFulfillmentsForEscrow: <ObligationData extends readonly abitype.AbiParameter[], DemandData extends readonly abitype.AbiParameter[]>(params: {
            escrow: {
                demandAbi: DemandData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
                refUID?: `0x${string}` | `0x${string}`[];
            };
            fulfillment: {
                obligationAbi: ObligationData;
                attester?: abitype.Address | abitype.Address[];
                recipient?: abitype.Address | abitype.Address[];
                schemaUID?: `0x${string}` | `0x${string}`[];
                uid?: `0x${string}` | `0x${string}`[];
            };
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_5]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never) extends infer T_3 ? { [key_2 in keyof T_3]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_4]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_3], abitype.AbiParameterKind>; } : never)[key_2]; } : never) => Promise<boolean | null>;
        } & {
            skipAlreadyArbitrated?: boolean;
            onAfterArbitrate?: (decision: {
                hash: `0x${string}`;
                attestation: Attestation;
                obligation: viem.DecodeAbiParametersReturnType<ObligationData>;
                demand: viem.DecodeAbiParametersReturnType<DemandData>;
                escrowAttestation: Attestation;
                decision: boolean | null;
            }) => Promise<void>;
            pollingInterval?: number;
        }) => Promise<{
            pastEscrows: {
                log: viem.Log<bigint, number, boolean, {
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }, undefined, [{
                    readonly name: "Attested";
                    readonly type: "event";
                    readonly inputs: readonly [{
                        readonly type: "address";
                        readonly name: "recipient";
                        readonly indexed: true;
                    }, {
                        readonly type: "address";
                        readonly name: "attester";
                        readonly indexed: true;
                    }, {
                        readonly type: "bytes32";
                        readonly name: "uid";
                    }, {
                        readonly type: "bytes32";
                        readonly name: "schemaUID";
                        readonly indexed: true;
                    }];
                }], "Attested">;
                attestation: {
                    uid: `0x${string}`;
                    schema: `0x${string}`;
                    time: bigint;
                    expirationTime: bigint;
                    revocationTime: bigint;
                    refUID: `0x${string}`;
                    recipient: `0x${string}`;
                    attester: `0x${string}`;
                    revocable: boolean;
                    data: `0x${string}`;
                };
                obligation: readonly [{
                    arbiter: `0x${string}`;
                    demand: `0x${string}`;
                }];
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never) extends infer T ? { [key in keyof T]: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<(DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[])[key_1], abitype.AbiParameterKind>; } : never)[key]; } : never;
            }[];
            unwatch: () => void;
        }>;
    };
};

type ViemClient = WalletClient<Transport, Chain, Account> & PublicActions;

/**
 * General Arbiters Client
 *
 * Handles basic arbiters that don't depend on specific attestation properties:
 * - IntrinsicsArbiter2: Schema-based validation
 * - TrustedPartyArbiter: Creator-based validation with composable base arbiter
 * - SpecificAttestationArbiter: Validates against a specific attestation UID
 * - TrustedOracleArbiter: Oracle-based decision making with arbitration requests
 *   - Supports requestArbitration for requesting arbitration from specific oracles
 *   - Provides listening functions for oracles to respond only to arbitration requests
 */
declare const makeGeneralArbitersClient: (viemClient: ViemClient, addresses: ChainAddresses) => {
    /**
     * Encodes IntrinsicsArbiter2.DemandData to bytes.
     * @param demand - struct DemandData {bytes32 schema}
     * @returns abi encoded bytes
     */
    encodeIntrinsics2Demand: (demand: {
        schema: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes IntrinsicsArbiter2.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeIntrinsics2Demand: (demandData: `0x${string}`) => {
        schema: `0x${string}`;
    };
    /**
     * Encodes TrustedPartyArbiter.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, address creator}
     * @returns abi encoded bytes
     */
    encodeTrustedPartyDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        creator: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes TrustedPartyArbiter.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeTrustedPartyDemand: (demandData: `0x${string}`) => {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        creator: `0x${string}`;
    };
    /**
     * Encodes SpecificAttestationArbiter.DemandData to bytes.
     * @param demand - struct DemandData {bytes32 uid}
     * @returns abi encoded bytes
     */
    encodeSpecificAttestationDemand: (demand: {
        uid: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes SpecificAttestationArbiter.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeSpecificAttestationDemand: (demandData: `0x${string}`) => {
        uid: `0x${string}`;
    };
    /**
     * Encodes TrustedOracleArbiter.DemandData to bytes.
     * @param demand - struct DemandData {address oracle, bytes data}
     * @returns abi encoded bytes
     */
    encodeTrustedOracleDemand: (demand: {
        oracle: `0x${string}`;
        data: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes TrustedOracleArbiter.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeTrustedOracleDemand: (demandData: `0x${string}`) => {
        oracle: `0x${string}`;
        data: `0x${string}`;
    };
    /**
     * Arbitrate on the validality of an obligation fulfilling
     * a demand for TrustedOracleArbiter
     * @param obligation - bytes32 obligation
     * @param decision - bool decision
     * @returns transaction hash
     */
    arbitrateAsTrustedOracle: (obligation: `0x${string}`, decision: boolean) => Promise<`0x${string}`>;
    /**
     * Request arbitration on an obligation from TrustedOracleArbiter
     * @param obligation - bytes32 obligation uid
     * @param oracle - address of the oracle to request arbitration from
     * @returns transaction hash
     */
    requestArbitrationFromTrustedOracle: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<`0x${string}`>;
    /**
     * Check if an arbitration has already been made for a specific obligation by a specific oracle
     * @param obligation - bytes32 obligation uid
     * @param oracle - address of the oracle
     * @returns the arbitration result if exists, undefined if not
     */
    checkExistingArbitration: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<{
        obligation: `0x${string}`;
        oracle: `0x${string}`;
        decision: boolean;
    } | undefined>;
    /**
     * Wait for an arbitration to be made on a TrustedOracleArbiter
     * @param obligation - bytes32 obligation uid
     * @param oracle - address of the oracle
     * @param pollingInterval - polling interval in milliseconds (default: 1000)
     * @returns the event args
     */
    waitForTrustedOracleArbitration: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
        obligation?: `0x${string}` | undefined;
        oracle?: `0x${string}` | undefined;
        decision?: boolean | undefined;
    }>;
    /**
     * Wait for an arbitration request to be made on a TrustedOracleArbiter
     * @param obligation - bytes32 obligation uid
     * @param oracle - address of the oracle
     * @param pollingInterval - polling interval in milliseconds (default: 1000)
     * @returns the event args
     */
    waitForTrustedOracleArbitrationRequest: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
        obligation?: `0x${string}` | undefined;
        oracle?: `0x${string}` | undefined;
    }>;
    /**
     * Listen for arbitration requests and only arbitrate on request
     * This function continuously listens for ArbitrationRequested events
     * and calls the provided arbitration handler for each request
     * @param oracle - address of the oracle (filter for requests to this oracle)
     * @param arbitrationHandler - function to handle arbitration requests
     * @param pollingInterval - polling interval in milliseconds (default: 1000)
     * @returns unwatch function to stop listening
     */
    listenForArbitrationRequestsOnly: (oracle: `0x${string}`, arbitrationHandler: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<boolean>, pollingInterval?: number) => viem.WatchEventReturnType;
};

/**
 * Attestation Properties Arbiters Client
 *
 * Handles arbiters that validate specific properties of attestations. Each arbiter type
 * comes in two variants:
 * - Composing: Can be combined with a base arbiter for additional validation
 * - Non-Composing: Standalone validation against the property
 *
 * Supported attestation properties:
 * - Attester: Validates the attester address
 * - Time: Validates timestamp (After/Before/Equal variants)
 * - ExpirationTime: Validates expiration timestamp (After/Before/Equal variants)
 * - Recipient: Validates the recipient address
 * - RefUID: Validates the reference UID
 * - Revocable: Validates the revocable flag
 * - Schema: Validates the schema hash
 * - UID: Validates the attestation UID
 */
declare const makeAttestationPropertiesArbitersClient: (viemClient: ViemClient, addresses: ChainAddresses) => {
    /**
     * Encodes AttesterArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, address attester}
     */
    encodeAttesterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        attester: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes AttesterArbiterComposing.DemandData from bytes.
     */
    decodeAttesterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes AttesterArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {address attester}
     */
    encodeAttesterArbiterNonComposingDemand: (demand: {
        attester: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes AttesterArbiterNonComposing.DemandData from bytes.
     */
    decodeAttesterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeAfterArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 time}
     */
    encodeTimeAfterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeAfterArbiterComposing.DemandData from bytes.
     */
    decodeTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeAfterArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 time}
     */
    encodeTimeAfterArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeAfterArbiterNonComposing.DemandData from bytes.
     */
    decodeTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeBeforeArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 time}
     */
    encodeTimeBeforeArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeBeforeArbiterComposing.DemandData from bytes.
     */
    decodeTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeBeforeArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 time}
     */
    encodeTimeBeforeArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeBeforeArbiterNonComposing.DemandData from bytes.
     */
    decodeTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeEqualArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 time}
     */
    encodeTimeEqualArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeEqualArbiterComposing.DemandData from bytes.
     */
    decodeTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes TimeEqualArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 time}
     */
    encodeTimeEqualArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    /**
     * Decodes TimeEqualArbiterNonComposing.DemandData from bytes.
     */
    decodeTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeAfterArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 expirationTime}
     */
    encodeExpirationTimeAfterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeAfterArbiterComposing.DemandData from bytes.
     */
    decodeExpirationTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeAfterArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 expirationTime}
     */
    encodeExpirationTimeAfterArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeAfterArbiterNonComposing.DemandData from bytes.
     */
    decodeExpirationTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeBeforeArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 expirationTime}
     */
    encodeExpirationTimeBeforeArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeBeforeArbiterComposing.DemandData from bytes.
     */
    decodeExpirationTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeBeforeArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 expirationTime}
     */
    encodeExpirationTimeBeforeArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeBeforeArbiterNonComposing.DemandData from bytes.
     */
    decodeExpirationTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeEqualArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, uint64 expirationTime}
     */
    encodeExpirationTimeEqualArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeEqualArbiterComposing.DemandData from bytes.
     */
    decodeExpirationTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes ExpirationTimeEqualArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {uint64 expirationTime}
     */
    encodeExpirationTimeEqualArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    /**
     * Decodes ExpirationTimeEqualArbiterNonComposing.DemandData from bytes.
     */
    decodeExpirationTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RecipientArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, address recipient}
     */
    encodeRecipientArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        recipient: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes RecipientArbiterComposing.DemandData from bytes.
     */
    decodeRecipientArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RecipientArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {address recipient}
     */
    encodeRecipientArbiterNonComposingDemand: (demand: {
        recipient: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes RecipientArbiterNonComposing.DemandData from bytes.
     */
    decodeRecipientArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RefUidArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, bytes32 refUID}
     */
    encodeRefUidArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        refUID: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes RefUidArbiterComposing.DemandData from bytes.
     */
    decodeRefUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RefUidArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {bytes32 refUID}
     */
    encodeRefUidArbiterNonComposingDemand: (demand: {
        refUID: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes RefUidArbiterNonComposing.DemandData from bytes.
     */
    decodeRefUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RevocableArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, bool revocable}
     */
    encodeRevocableArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        revocable: boolean;
    }) => `0x${string}`;
    /**
     * Decodes RevocableArbiterComposing.DemandData from bytes.
     */
    decodeRevocableArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes RevocableArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {bool revocable}
     */
    encodeRevocableArbiterNonComposingDemand: (demand: {
        revocable: boolean;
    }) => `0x${string}`;
    /**
     * Decodes RevocableArbiterNonComposing.DemandData from bytes.
     */
    decodeRevocableArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes SchemaArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, bytes32 schema}
     */
    encodeSchemaArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        schema: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes SchemaArbiterComposing.DemandData from bytes.
     */
    decodeSchemaArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes SchemaArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {bytes32 schema}
     */
    encodeSchemaArbiterNonComposingDemand: (demand: {
        schema: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes SchemaArbiterNonComposing.DemandData from bytes.
     */
    decodeSchemaArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes UidArbiterComposing.DemandData to bytes.
     * @param demand - struct DemandData {address baseArbiter, bytes baseDemand, bytes32 uid}
     */
    encodeUidArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        uid: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes UidArbiterComposing.DemandData from bytes.
     */
    decodeUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
    /**
     * Encodes UidArbiterNonComposing.DemandData to bytes.
     * @param demand - struct DemandData {bytes32 uid}
     */
    encodeUidArbiterNonComposingDemand: (demand: {
        uid: `0x${string}`;
    }) => `0x${string}`;
    /**
     * Decodes UidArbiterNonComposing.DemandData from bytes.
     */
    decodeUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
};

/**
 * Logical Arbiters Client
 *
 * Handles logical composition arbiters for combining multiple arbiters:
 * - AnyArbiter: Returns true if ANY of the provided arbiters returns true (logical OR)
 * - AllArbiter: Returns true if ALL of the provided arbiters return true (logical AND)
 *
 * These arbiters take arrays of arbiter addresses and their corresponding demand data,
 * allowing for complex logical compositions of arbitration rules.
 */
declare const makeLogicalArbitersClient: (viemClient: ViemClient, addresses: ChainAddresses) => {
    /**
     * Encodes AnyArbiter.DemandData to bytes.
     * @param demand - struct DemandData {address[] arbiters, bytes[] demands}
     * @returns abi encoded bytes
     */
    encodeAnyArbiterDemand: (demand: {
        arbiters: `0x${string}`[];
        demands: `0x${string}`[];
    }) => `0x${string}`;
    /**
     * Decodes AnyArbiter.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeAnyArbiterDemand: (demandData: `0x${string}`) => {
        arbiters: readonly `0x${string}`[];
        demands: readonly `0x${string}`[];
    };
    /**
     * Encodes AllArbiter.DemandData to bytes.
     * @param demand - struct DemandData {address[] arbiters, bytes[] demands}
     * @returns abi encoded bytes
     */
    encodeAllArbiterDemand: (demand: {
        arbiters: `0x${string}`[];
        demands: `0x${string}`[];
    }) => `0x${string}`;
    /**
     * Decodes AllArbiter.DemandData from bytes.
     * @param demandData - DemandData as abi encoded bytes
     * @returns the decoded DemandData object
     */
    decodeAllArbiterDemand: (demandData: `0x${string}`) => {
        arbiters: readonly `0x${string}`[];
        demands: readonly `0x${string}`[];
    };
};

/**
 * Unified Arbiters Client
 *
 * Provides a single interface for all arbiter functionality by combining:
 * - General arbiters (TrustedParty, SpecificAttestation, TrustedOracle, etc.)
 * - Logical arbiters (Any, All)
 * - Attestation properties arbiters (Attester, Time, Schema, etc.)
 */
declare const makeArbitersClient: (viemClient: ViemClient, addresses: ChainAddresses) => {
    /**
     * @deprecated Use encodeAnyArbiterDemand instead
     */
    encodeMultiArbiterDemand: (demand: {
        arbiters: `0x${string}`[];
        demands: `0x${string}`[];
    }) => `0x${string}`;
    /**
     * @deprecated Use decodeAnyArbiterDemand instead
     */
    decodeMultiArbiterDemand: (demandData: `0x${string}`) => {
        arbiters: readonly `0x${string}`[];
        demands: readonly `0x${string}`[];
    };
    encodeAttesterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        attester: `0x${string}`;
    }) => `0x${string}`;
    decodeAttesterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeAttesterArbiterNonComposingDemand: (demand: {
        attester: `0x${string}`;
    }) => `0x${string}`;
    decodeAttesterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeAfterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    decodeTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeAfterArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    decodeTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeBeforeArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    decodeTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeBeforeArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    decodeTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeEqualArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        time: bigint;
    }) => `0x${string}`;
    decodeTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeTimeEqualArbiterNonComposingDemand: (demand: {
        time: bigint;
    }) => `0x${string}`;
    decodeTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeAfterArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeAfterArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeAfterArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeAfterArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeBeforeArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeBeforeArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeBeforeArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeBeforeArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeEqualArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeEqualArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeExpirationTimeEqualArbiterNonComposingDemand: (demand: {
        expirationTime: bigint;
    }) => `0x${string}`;
    decodeExpirationTimeEqualArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeRecipientArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        recipient: `0x${string}`;
    }) => `0x${string}`;
    decodeRecipientArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeRecipientArbiterNonComposingDemand: (demand: {
        recipient: `0x${string}`;
    }) => `0x${string}`;
    decodeRecipientArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeRefUidArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        refUID: `0x${string}`;
    }) => `0x${string}`;
    decodeRefUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeRefUidArbiterNonComposingDemand: (demand: {
        refUID: `0x${string}`;
    }) => `0x${string}`;
    decodeRefUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeRevocableArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        revocable: boolean;
    }) => `0x${string}`;
    decodeRevocableArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeRevocableArbiterNonComposingDemand: (demand: {
        revocable: boolean;
    }) => `0x${string}`;
    decodeRevocableArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeSchemaArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        schema: `0x${string}`;
    }) => `0x${string}`;
    decodeSchemaArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeSchemaArbiterNonComposingDemand: (demand: {
        schema: `0x${string}`;
    }) => `0x${string}`;
    decodeSchemaArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeUidArbiterComposingDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        uid: `0x${string}`;
    }) => `0x${string}`;
    decodeUidArbiterComposingDemand: (demandData: `0x${string}`) => any;
    encodeUidArbiterNonComposingDemand: (demand: {
        uid: `0x${string}`;
    }) => `0x${string}`;
    decodeUidArbiterNonComposingDemand: (demandData: `0x${string}`) => any;
    encodeAnyArbiterDemand: (demand: {
        arbiters: `0x${string}`[];
        demands: `0x${string}`[];
    }) => `0x${string}`;
    decodeAnyArbiterDemand: (demandData: `0x${string}`) => {
        arbiters: readonly `0x${string}`[];
        demands: readonly `0x${string}`[];
    };
    encodeAllArbiterDemand: (demand: {
        arbiters: `0x${string}`[];
        demands: `0x${string}`[];
    }) => `0x${string}`;
    decodeAllArbiterDemand: (demandData: `0x${string}`) => {
        arbiters: readonly `0x${string}`[];
        demands: readonly `0x${string}`[];
    };
    encodeIntrinsics2Demand: (demand: {
        schema: `0x${string}`;
    }) => `0x${string}`;
    decodeIntrinsics2Demand: (demandData: `0x${string}`) => {
        schema: `0x${string}`;
    };
    encodeTrustedPartyDemand: (demand: {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        creator: `0x${string}`;
    }) => `0x${string}`;
    decodeTrustedPartyDemand: (demandData: `0x${string}`) => {
        baseArbiter: `0x${string}`;
        baseDemand: `0x${string}`;
        creator: `0x${string}`;
    };
    encodeSpecificAttestationDemand: (demand: {
        uid: `0x${string}`;
    }) => `0x${string}`;
    decodeSpecificAttestationDemand: (demandData: `0x${string}`) => {
        uid: `0x${string}`;
    };
    encodeTrustedOracleDemand: (demand: {
        oracle: `0x${string}`;
        data: `0x${string}`;
    }) => `0x${string}`;
    decodeTrustedOracleDemand: (demandData: `0x${string}`) => {
        oracle: `0x${string}`;
        data: `0x${string}`;
    };
    arbitrateAsTrustedOracle: (obligation: `0x${string}`, decision: boolean) => Promise<`0x${string}`>;
    requestArbitrationFromTrustedOracle: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<`0x${string}`>;
    checkExistingArbitration: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<{
        obligation: `0x${string}`;
        oracle: `0x${string}`;
        decision: boolean;
    } | undefined>;
    waitForTrustedOracleArbitration: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
        obligation?: `0x${string}` | undefined;
        oracle?: `0x${string}` | undefined;
        decision?: boolean | undefined;
    }>;
    waitForTrustedOracleArbitrationRequest: (obligation: `0x${string}`, oracle: `0x${string}`, pollingInterval?: number) => Promise<{
        obligation?: `0x${string}` | undefined;
        oracle?: `0x${string}` | undefined;
    }>;
    listenForArbitrationRequestsOnly: (oracle: `0x${string}`, arbitrationHandler: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<boolean>, pollingInterval?: number) => viem.WatchEventReturnType;
};

/**
 * Creates an Alkahest client for interacting with the protocol
 * @param walletClient - Viem wallet client object
 * @param contractAddresses - Optional custom contract addresses (useful for local testing)
 * @returns Client object with methods for interacting with different token standards and attestations
 *
 * @example
 * ```ts
 * const client = makeClient(
 *   privateKeyToAccount(process.env.PRIVKEY as `0x${string}`, {
 *     nonceManager, // automatic nonce management
 *   })
 * );
 * ```
 */
declare const makeClient: (walletClient: WalletClient<Transport, Chain, Account>, contractAddresses?: Partial<ChainAddresses>) => any;
/**
 * Creates a minimal Alkahest client with only core functionality
 * @param walletClient - Viem wallet client object
 * @param contractAddresses - Optional custom contract addresses (useful for local testing)
 * @returns Minimal client object that can be extended with additional functionality
 *
 * @example
 * ```ts
 * // Create minimal client
 * const baseClient = makeMinimalClient(walletClient);
 *
 * // Extend with default functionality
 * const fullClient = baseClient.extend(makeDefaultExtension);
 *
 * // Or extend with custom functionality
 * const customClient = baseClient.extend((client) => ({
 *   erc20: makeErc20Client(client.viemClient, client.contractAddresses),
 *   customMethod: () => "custom functionality"
 * }));
 * ```
 */
declare const makeMinimalClient: (walletClient: WalletClient<Transport, Chain, Account>, contractAddresses?: Partial<ChainAddresses>) => any;

export { type ApprovalPurpose, type Attestation, type AttestationFilters, type BatchFilters, type BlockFilters, type ChainAddresses, type Demand, type Eip2612Props, type EnhancedArbitrateFilters, type Erc1155, type Erc20, type Erc721, type PerformanceFilters, type PermitSignature, type SignPermitProps, type TimeFilters, type TokenBundle, type TokenBundleFlat, contractAddresses, makeArbitersClient, makeAttestationPropertiesArbitersClient, makeClient, makeDefaultExtension, makeExtendableClient, makeGeneralArbitersClient, makeLogicalArbitersClient, makeMinimalClient, supportedChains };
