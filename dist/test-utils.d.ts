import { createAnvil } from '@viem/anvil';
import * as viem from 'viem';
import { BlockNumber, BlockTag, WalletClient, Transport, Chain, Account, Client, PublicActions, TestClient, WalletActions } from 'viem';
import * as arktype from 'arktype';
import * as zod from 'zod';
import { Hex } from '../../types/misc.js';
import { Prettify } from '../../types/utils.js';
import { ValidateSiweMessageParameters } from '../../utils/siwe/validateSiweMessage.js';
import { VerifyHashParameters } from '../public/verifyHash.js';
import * as abitype from 'abitype';

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
    commitObligation: `0x${string}`;
    trustedPartyArbiter: `0x${string}`;
    trivialArbiter: `0x${string}`;
    specificAttestationArbiter: `0x${string}`;
    trustedOracleArbiter: `0x${string}`;
    commitTestsArbiter: `0x${string}`;
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

type VerifySiweMessageParameters = Prettify<Pick<VerifyHashParameters, 'blockNumber' | 'blockTag'> & Pick<ValidateSiweMessageParameters, 'address' | 'domain' | 'nonce' | 'scheme' | 'time'> & {
    /**
     * EIP-4361 formatted message.
     */
    message: string;
    /**
     * Signature to check against.
     */
    signature: Hex;
}>;
type VerifySiweMessageReturnType = boolean;

declare enum CommitAlgo {
    SHA256 = 0,
    MD5 = 1
}
type CommitObligationData = {
    commitHash: string;
    commitAlgo: CommitAlgo;
    hosts: string[];
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
declare const makeClient: (walletClient: WalletClient<Transport, Chain, Account>, contractAddresses?: Partial<ChainAddresses>) => {
    /** The underlying Viem client */
    viemClient: viem.Client<Transport, Chain, Account, viem.WalletRpcSchema, {
        call: (parameters: viem.CallParameters<Chain>) => Promise<viem.CallReturnType>;
        createAccessList: (parameters: viem.CreateAccessListParameters<Chain>) => Promise<{
            accessList: viem.AccessList;
            gasUsed: bigint;
        }>;
        createBlockFilter: () => Promise<viem.CreateBlockFilterReturnType>;
        createContractEventFilter: <const abi extends abitype.Abi | readonly unknown[], eventName extends viem.ContractEventName<abi> | undefined, args extends viem.MaybeExtractEventArgsFromAbi<abi, eventName> | undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined>(args: viem.CreateContractEventFilterParameters<abi, eventName, args, strict, fromBlock, toBlock>) => Promise<viem.CreateContractEventFilterReturnType<abi, eventName, args, strict, fromBlock, toBlock>>;
        createEventFilter: <const abiEvent extends abitype.AbiEvent | undefined = undefined, const abiEvents extends readonly abitype.AbiEvent[] | readonly unknown[] | undefined = abiEvent extends abitype.AbiEvent ? [abiEvent] : undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, _EventName extends string | undefined = viem.MaybeAbiEventName<abiEvent>, _Args extends viem.MaybeExtractEventArgsFromAbi<abiEvents, _EventName> | undefined = undefined>(args?: viem.CreateEventFilterParameters<abiEvent, abiEvents, strict, fromBlock, toBlock, _EventName, _Args> | undefined) => Promise<viem.CreateEventFilterReturnType<abiEvent, abiEvents, strict, fromBlock, toBlock, _EventName, _Args>>;
        createPendingTransactionFilter: () => Promise<viem.CreatePendingTransactionFilterReturnType>;
        estimateContractGas: <chain extends Chain | undefined, const abi extends abitype.Abi | readonly unknown[], functionName extends viem.ContractFunctionName<abi, "nonpayable" | "payable">, args extends viem.ContractFunctionArgs<abi, "nonpayable" | "payable", functionName>>(args: viem.EstimateContractGasParameters<abi, functionName, args, chain>) => Promise<viem.EstimateContractGasReturnType>;
        estimateGas: (args: viem.EstimateGasParameters<Chain>) => Promise<viem.EstimateGasReturnType>;
        getBalance: (args: viem.GetBalanceParameters) => Promise<viem.GetBalanceReturnType>;
        getBlobBaseFee: () => Promise<viem.GetBlobBaseFeeReturnType>;
        getBlock: <includeTransactions extends boolean = false, blockTag extends viem.BlockTag = "latest">(args?: viem.GetBlockParameters<includeTransactions, blockTag> | undefined) => Promise<{
            number: blockTag extends "pending" ? null : bigint;
            timestamp: bigint;
            nonce: blockTag extends "pending" ? null : `0x${string}`;
            hash: blockTag extends "pending" ? null : `0x${string}`;
            logsBloom: blockTag extends "pending" ? null : `0x${string}`;
            baseFeePerGas: bigint | null;
            blobGasUsed: bigint;
            difficulty: bigint;
            excessBlobGas: bigint;
            extraData: viem.Hex;
            gasLimit: bigint;
            gasUsed: bigint;
            miner: abitype.Address;
            mixHash: viem.Hash;
            parentBeaconBlockRoot?: `0x${string}` | undefined;
            parentHash: viem.Hash;
            receiptsRoot: viem.Hex;
            sealFields: viem.Hex[];
            sha3Uncles: viem.Hash;
            size: bigint;
            stateRoot: viem.Hash;
            totalDifficulty: bigint | null;
            transactionsRoot: viem.Hash;
            uncles: viem.Hash[];
            withdrawals?: viem.Withdrawal[] | undefined | undefined;
            withdrawalsRoot?: `0x${string}` | undefined;
            transactions: includeTransactions extends true ? ({
                value: bigint;
                v: bigint;
                r: viem.Hex;
                s: viem.Hex;
                type: "legacy";
                chainId?: number | undefined;
                yParity?: undefined | undefined;
                to: abitype.Address | null;
                from: abitype.Address;
                gas: bigint;
                nonce: number;
                maxFeePerBlobGas?: undefined | undefined;
                gasPrice: bigint;
                maxFeePerGas?: undefined | undefined;
                maxPriorityFeePerGas?: undefined | undefined;
                accessList?: undefined | undefined;
                blobVersionedHashes?: undefined | undefined;
                authorizationList?: undefined | undefined;
                hash: viem.Hash;
                input: viem.Hex;
                typeHex: viem.Hex | null;
                blockNumber: (blockTag extends "pending" ? true : false) extends infer T ? T extends (blockTag extends "pending" ? true : false) ? T extends true ? null : bigint : never : never;
                blockHash: (blockTag extends "pending" ? true : false) extends infer T_1 ? T_1 extends (blockTag extends "pending" ? true : false) ? T_1 extends true ? null : `0x${string}` : never : never;
                transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_2 ? T_2 extends (blockTag extends "pending" ? true : false) ? T_2 extends true ? null : number : never : never;
            } | {
                value: bigint;
                v: bigint;
                r: viem.Hex;
                s: viem.Hex;
                type: "eip2930";
                chainId: number;
                yParity: number;
                to: abitype.Address | null;
                from: abitype.Address;
                gas: bigint;
                nonce: number;
                maxFeePerBlobGas?: undefined | undefined;
                gasPrice: bigint;
                maxFeePerGas?: undefined | undefined;
                maxPriorityFeePerGas?: undefined | undefined;
                accessList: viem.AccessList;
                blobVersionedHashes?: undefined | undefined;
                authorizationList?: undefined | undefined;
                hash: viem.Hash;
                input: viem.Hex;
                typeHex: viem.Hex | null;
                blockNumber: (blockTag extends "pending" ? true : false) extends infer T_3 ? T_3 extends (blockTag extends "pending" ? true : false) ? T_3 extends true ? null : bigint : never : never;
                blockHash: (blockTag extends "pending" ? true : false) extends infer T_4 ? T_4 extends (blockTag extends "pending" ? true : false) ? T_4 extends true ? null : `0x${string}` : never : never;
                transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_5 ? T_5 extends (blockTag extends "pending" ? true : false) ? T_5 extends true ? null : number : never : never;
            } | {
                value: bigint;
                v: bigint;
                r: viem.Hex;
                s: viem.Hex;
                type: "eip1559";
                chainId: number;
                yParity: number;
                to: abitype.Address | null;
                from: abitype.Address;
                gas: bigint;
                nonce: number;
                maxFeePerBlobGas?: undefined | undefined;
                gasPrice?: undefined | undefined;
                maxFeePerGas: bigint;
                maxPriorityFeePerGas: bigint;
                accessList: viem.AccessList;
                blobVersionedHashes?: undefined | undefined;
                authorizationList?: undefined | undefined;
                hash: viem.Hash;
                input: viem.Hex;
                typeHex: viem.Hex | null;
                blockNumber: (blockTag extends "pending" ? true : false) extends infer T_6 ? T_6 extends (blockTag extends "pending" ? true : false) ? T_6 extends true ? null : bigint : never : never;
                blockHash: (blockTag extends "pending" ? true : false) extends infer T_7 ? T_7 extends (blockTag extends "pending" ? true : false) ? T_7 extends true ? null : `0x${string}` : never : never;
                transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_8 ? T_8 extends (blockTag extends "pending" ? true : false) ? T_8 extends true ? null : number : never : never;
            } | {
                value: bigint;
                v: bigint;
                r: viem.Hex;
                s: viem.Hex;
                type: "eip4844";
                chainId: number;
                yParity: number;
                to: abitype.Address | null;
                from: abitype.Address;
                gas: bigint;
                nonce: number;
                maxFeePerBlobGas: bigint;
                gasPrice?: undefined | undefined;
                maxFeePerGas: bigint;
                maxPriorityFeePerGas: bigint;
                accessList: viem.AccessList;
                blobVersionedHashes: readonly viem.Hex[];
                authorizationList?: undefined | undefined;
                hash: viem.Hash;
                input: viem.Hex;
                typeHex: viem.Hex | null;
                blockNumber: (blockTag extends "pending" ? true : false) extends infer T_9 ? T_9 extends (blockTag extends "pending" ? true : false) ? T_9 extends true ? null : bigint : never : never;
                blockHash: (blockTag extends "pending" ? true : false) extends infer T_10 ? T_10 extends (blockTag extends "pending" ? true : false) ? T_10 extends true ? null : `0x${string}` : never : never;
                transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_11 ? T_11 extends (blockTag extends "pending" ? true : false) ? T_11 extends true ? null : number : never : never;
            } | {
                value: bigint;
                v: bigint;
                r: viem.Hex;
                s: viem.Hex;
                type: "eip7702";
                chainId: number;
                yParity: number;
                to: abitype.Address | null;
                from: abitype.Address;
                gas: bigint;
                nonce: number;
                maxFeePerBlobGas?: undefined | undefined;
                gasPrice?: undefined | undefined;
                maxFeePerGas: bigint;
                maxPriorityFeePerGas: bigint;
                accessList: viem.AccessList;
                blobVersionedHashes?: undefined | undefined;
                authorizationList: viem.SignedAuthorizationList;
                hash: viem.Hash;
                input: viem.Hex;
                typeHex: viem.Hex | null;
                blockNumber: (blockTag extends "pending" ? true : false) extends infer T_12 ? T_12 extends (blockTag extends "pending" ? true : false) ? T_12 extends true ? null : bigint : never : never;
                blockHash: (blockTag extends "pending" ? true : false) extends infer T_13 ? T_13 extends (blockTag extends "pending" ? true : false) ? T_13 extends true ? null : `0x${string}` : never : never;
                transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_14 ? T_14 extends (blockTag extends "pending" ? true : false) ? T_14 extends true ? null : number : never : never;
            })[] : `0x${string}`[];
        }>;
        getBlockNumber: (args?: viem.GetBlockNumberParameters | undefined) => Promise<viem.GetBlockNumberReturnType>;
        getBlockTransactionCount: (args?: viem.GetBlockTransactionCountParameters | undefined) => Promise<viem.GetBlockTransactionCountReturnType>;
        getBytecode: (args: viem.GetBytecodeParameters) => Promise<viem.GetBytecodeReturnType>;
        getChainId: () => Promise<viem.GetChainIdReturnType>;
        getCode: (args: viem.GetBytecodeParameters) => Promise<viem.GetBytecodeReturnType>;
        getContractEvents: <const abi extends abitype.Abi | readonly unknown[], eventName extends viem.ContractEventName<abi> | undefined = undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined>(args: viem.GetContractEventsParameters<abi, eventName, strict, fromBlock, toBlock>) => Promise<viem.GetContractEventsReturnType<abi, eventName, strict, fromBlock, toBlock>>;
        getEip712Domain: (args: viem.GetEip712DomainParameters) => Promise<viem.GetEip712DomainReturnType>;
        getEnsAddress: (args: viem.GetEnsAddressParameters) => Promise<viem.GetEnsAddressReturnType>;
        getEnsAvatar: (args: viem.GetEnsAvatarParameters) => Promise<viem.GetEnsAvatarReturnType>;
        getEnsName: (args: viem.GetEnsNameParameters) => Promise<viem.GetEnsNameReturnType>;
        getEnsResolver: (args: viem.GetEnsResolverParameters) => Promise<viem.GetEnsResolverReturnType>;
        getEnsText: (args: viem.GetEnsTextParameters) => Promise<viem.GetEnsTextReturnType>;
        getFeeHistory: (args: viem.GetFeeHistoryParameters) => Promise<viem.GetFeeHistoryReturnType>;
        estimateFeesPerGas: <chainOverride extends Chain | undefined = undefined, type extends viem.FeeValuesType = "eip1559">(args?: viem.EstimateFeesPerGasParameters<Chain, chainOverride, type> | undefined) => Promise<viem.EstimateFeesPerGasReturnType<type>>;
        getFilterChanges: <filterType extends viem.FilterType, const abi extends abitype.Abi | readonly unknown[] | undefined, eventName extends string | undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined>(args: viem.GetFilterChangesParameters<filterType, abi, eventName, strict, fromBlock, toBlock>) => Promise<viem.GetFilterChangesReturnType<filterType, abi, eventName, strict, fromBlock, toBlock>>;
        getFilterLogs: <const abi extends abitype.Abi | readonly unknown[] | undefined, eventName extends string | undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined>(args: viem.GetFilterLogsParameters<abi, eventName, strict, fromBlock, toBlock>) => Promise<viem.GetFilterLogsReturnType<abi, eventName, strict, fromBlock, toBlock>>;
        getGasPrice: () => Promise<viem.GetGasPriceReturnType>;
        getLogs: <const abiEvent extends abitype.AbiEvent | undefined = undefined, const abiEvents extends readonly abitype.AbiEvent[] | readonly unknown[] | undefined = abiEvent extends abitype.AbiEvent ? [abiEvent] : undefined, strict extends boolean | undefined = undefined, fromBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined, toBlock extends viem.BlockNumber | viem.BlockTag | undefined = undefined>(args?: viem.GetLogsParameters<abiEvent, abiEvents, strict, fromBlock, toBlock> | undefined) => Promise<viem.GetLogsReturnType<abiEvent, abiEvents, strict, fromBlock, toBlock>>;
        getProof: (args: viem.GetProofParameters) => Promise<viem.GetProofReturnType>;
        estimateMaxPriorityFeePerGas: <chainOverride extends Chain | undefined = undefined>(args?: {
            chain?: chainOverride | null | undefined;
        } | undefined) => Promise<viem.EstimateMaxPriorityFeePerGasReturnType>;
        getStorageAt: (args: viem.GetStorageAtParameters) => Promise<viem.GetStorageAtReturnType>;
        getTransaction: <blockTag extends viem.BlockTag = "latest">(args: viem.GetTransactionParameters<blockTag>) => Promise<{
            value: bigint;
            v: bigint;
            r: viem.Hex;
            s: viem.Hex;
            type: "legacy";
            chainId?: number | undefined;
            yParity?: undefined | undefined;
            to: abitype.Address | null;
            from: abitype.Address;
            gas: bigint;
            nonce: number;
            maxFeePerBlobGas?: undefined | undefined;
            gasPrice: bigint;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
            accessList?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            authorizationList?: undefined | undefined;
            hash: viem.Hash;
            input: viem.Hex;
            typeHex: viem.Hex | null;
            blockNumber: (blockTag extends "pending" ? true : false) extends infer T ? T extends (blockTag extends "pending" ? true : false) ? T extends true ? null : bigint : never : never;
            blockHash: (blockTag extends "pending" ? true : false) extends infer T_1 ? T_1 extends (blockTag extends "pending" ? true : false) ? T_1 extends true ? null : `0x${string}` : never : never;
            transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_2 ? T_2 extends (blockTag extends "pending" ? true : false) ? T_2 extends true ? null : number : never : never;
        } | {
            value: bigint;
            v: bigint;
            r: viem.Hex;
            s: viem.Hex;
            type: "eip2930";
            chainId: number;
            yParity: number;
            to: abitype.Address | null;
            from: abitype.Address;
            gas: bigint;
            nonce: number;
            maxFeePerBlobGas?: undefined | undefined;
            gasPrice: bigint;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
            accessList: viem.AccessList;
            blobVersionedHashes?: undefined | undefined;
            authorizationList?: undefined | undefined;
            hash: viem.Hash;
            input: viem.Hex;
            typeHex: viem.Hex | null;
            blockNumber: (blockTag extends "pending" ? true : false) extends infer T_3 ? T_3 extends (blockTag extends "pending" ? true : false) ? T_3 extends true ? null : bigint : never : never;
            blockHash: (blockTag extends "pending" ? true : false) extends infer T_4 ? T_4 extends (blockTag extends "pending" ? true : false) ? T_4 extends true ? null : `0x${string}` : never : never;
            transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_5 ? T_5 extends (blockTag extends "pending" ? true : false) ? T_5 extends true ? null : number : never : never;
        } | {
            value: bigint;
            v: bigint;
            r: viem.Hex;
            s: viem.Hex;
            type: "eip1559";
            chainId: number;
            yParity: number;
            to: abitype.Address | null;
            from: abitype.Address;
            gas: bigint;
            nonce: number;
            maxFeePerBlobGas?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerGas: bigint;
            maxPriorityFeePerGas: bigint;
            accessList: viem.AccessList;
            blobVersionedHashes?: undefined | undefined;
            authorizationList?: undefined | undefined;
            hash: viem.Hash;
            input: viem.Hex;
            typeHex: viem.Hex | null;
            blockNumber: (blockTag extends "pending" ? true : false) extends infer T_6 ? T_6 extends (blockTag extends "pending" ? true : false) ? T_6 extends true ? null : bigint : never : never;
            blockHash: (blockTag extends "pending" ? true : false) extends infer T_7 ? T_7 extends (blockTag extends "pending" ? true : false) ? T_7 extends true ? null : `0x${string}` : never : never;
            transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_8 ? T_8 extends (blockTag extends "pending" ? true : false) ? T_8 extends true ? null : number : never : never;
        } | {
            value: bigint;
            v: bigint;
            r: viem.Hex;
            s: viem.Hex;
            type: "eip4844";
            chainId: number;
            yParity: number;
            to: abitype.Address | null;
            from: abitype.Address;
            gas: bigint;
            nonce: number;
            maxFeePerBlobGas: bigint;
            gasPrice?: undefined | undefined;
            maxFeePerGas: bigint;
            maxPriorityFeePerGas: bigint;
            accessList: viem.AccessList;
            blobVersionedHashes: readonly viem.Hex[];
            authorizationList?: undefined | undefined;
            hash: viem.Hash;
            input: viem.Hex;
            typeHex: viem.Hex | null;
            blockNumber: (blockTag extends "pending" ? true : false) extends infer T_9 ? T_9 extends (blockTag extends "pending" ? true : false) ? T_9 extends true ? null : bigint : never : never;
            blockHash: (blockTag extends "pending" ? true : false) extends infer T_10 ? T_10 extends (blockTag extends "pending" ? true : false) ? T_10 extends true ? null : `0x${string}` : never : never;
            transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_11 ? T_11 extends (blockTag extends "pending" ? true : false) ? T_11 extends true ? null : number : never : never;
        } | {
            value: bigint;
            v: bigint;
            r: viem.Hex;
            s: viem.Hex;
            type: "eip7702";
            chainId: number;
            yParity: number;
            to: abitype.Address | null;
            from: abitype.Address;
            gas: bigint;
            nonce: number;
            maxFeePerBlobGas?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerGas: bigint;
            maxPriorityFeePerGas: bigint;
            accessList: viem.AccessList;
            blobVersionedHashes?: undefined | undefined;
            authorizationList: viem.SignedAuthorizationList;
            hash: viem.Hash;
            input: viem.Hex;
            typeHex: viem.Hex | null;
            blockNumber: (blockTag extends "pending" ? true : false) extends infer T_12 ? T_12 extends (blockTag extends "pending" ? true : false) ? T_12 extends true ? null : bigint : never : never;
            blockHash: (blockTag extends "pending" ? true : false) extends infer T_13 ? T_13 extends (blockTag extends "pending" ? true : false) ? T_13 extends true ? null : `0x${string}` : never : never;
            transactionIndex: (blockTag extends "pending" ? true : false) extends infer T_14 ? T_14 extends (blockTag extends "pending" ? true : false) ? T_14 extends true ? null : number : never : never;
        }>;
        getTransactionConfirmations: (args: viem.GetTransactionConfirmationsParameters<Chain>) => Promise<viem.GetTransactionConfirmationsReturnType>;
        getTransactionCount: (args: viem.GetTransactionCountParameters) => Promise<viem.GetTransactionCountReturnType>;
        getTransactionReceipt: (args: viem.GetTransactionReceiptParameters) => Promise<viem.TransactionReceipt>;
        multicall: <const contracts extends readonly unknown[], allowFailure extends boolean = true>(args: viem.MulticallParameters<contracts, allowFailure>) => Promise<viem.MulticallReturnType<contracts, allowFailure>>;
        prepareTransactionRequest: <const request extends viem.PrepareTransactionRequestRequest<Chain, chainOverride>, chainOverride extends Chain | undefined = undefined, accountOverride extends Account | abitype.Address | undefined = undefined>(args: viem.PrepareTransactionRequestParameters<Chain, Account, chainOverride, accountOverride, request>) => Promise<viem.UnionRequiredBy<Extract<viem.UnionOmit<viem.ExtractChainFormatterParameters<viem.DeriveChain<Chain, chainOverride>, "transactionRequest", viem.TransactionRequest>, "from"> & (viem.DeriveChain<Chain, chainOverride> extends infer T_1 ? T_1 extends viem.DeriveChain<Chain, chainOverride> ? T_1 extends Chain ? {
            chain: T_1;
        } : {
            chain?: undefined;
        } : never : never) & (viem.DeriveAccount<Account, accountOverride> extends infer T_2 ? T_2 extends viem.DeriveAccount<Account, accountOverride> ? T_2 extends Account ? {
            account: T_2;
            from: abitype.Address;
        } : {
            account?: undefined;
            from?: undefined;
        } : never : never), viem.IsNever<((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_3 ? T_3 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_3 extends "legacy" ? viem.TransactionRequestLegacy : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_4 ? T_4 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_4 extends "eip1559" ? viem.TransactionRequestEIP1559 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_5 ? T_5 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_5 extends "eip2930" ? viem.TransactionRequestEIP2930 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_6 ? T_6 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_6 extends "eip4844" ? viem.TransactionRequestEIP4844 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_7 ? T_7 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_7 extends "eip7702" ? viem.TransactionRequestEIP7702 : never : never : never)> extends true ? unknown : viem.ExactPartial<((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_8 ? T_8 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_8 extends "legacy" ? viem.TransactionRequestLegacy : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_9 ? T_9 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_9 extends "eip1559" ? viem.TransactionRequestEIP1559 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_10 ? T_10 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_10 extends "eip2930" ? viem.TransactionRequestEIP2930 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_11 ? T_11 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_11 extends "eip4844" ? viem.TransactionRequestEIP4844 : never : never : never) | ((request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) extends infer T_12 ? T_12 extends (request["type"] extends string | undefined ? request["type"] : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)> extends "legacy" ? unknown : viem.GetTransactionType<request, (request extends {
            accessList?: undefined | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & viem.FeeValuesLegacy ? "legacy" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } & (viem.OneOf<{
            maxFeePerGas: viem.FeeValuesEIP1559["maxFeePerGas"];
        } | {
            maxPriorityFeePerGas: viem.FeeValuesEIP1559["maxPriorityFeePerGas"];
        }, viem.FeeValuesEIP1559> & {
            accessList?: viem.TransactionSerializableEIP2930["accessList"] | undefined;
        }) ? "eip1559" : never) | (request extends {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: bigint | undefined;
            sidecars?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: undefined | undefined;
            maxPriorityFeePerGas?: undefined | undefined;
        } & {
            accessList: viem.TransactionSerializableEIP2930["accessList"];
        } ? "eip2930" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: undefined | undefined;
            blobs?: readonly `0x${string}`[] | readonly viem.ByteArray[] | undefined;
            blobVersionedHashes?: readonly `0x${string}`[] | undefined;
            maxFeePerBlobGas?: bigint | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: false | readonly viem.BlobSidecar<`0x${string}`>[] | undefined;
        }) & (viem.ExactPartial<viem.FeeValuesEIP4844> & viem.OneOf<{
            blobs: viem.TransactionSerializableEIP4844["blobs"];
        } | {
            blobVersionedHashes: viem.TransactionSerializableEIP4844["blobVersionedHashes"];
        } | {
            sidecars: viem.TransactionSerializableEIP4844["sidecars"];
        }, viem.TransactionSerializableEIP4844>) ? "eip4844" : never) | (request extends ({
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        } | {
            accessList?: viem.AccessList | undefined;
            authorizationList?: viem.SignedAuthorizationList | undefined;
            blobs?: undefined | undefined;
            blobVersionedHashes?: undefined | undefined;
            gasPrice?: undefined | undefined;
            maxFeePerBlobGas?: undefined | undefined;
            maxFeePerGas?: bigint | undefined;
            maxPriorityFeePerGas?: bigint | undefined;
            sidecars?: undefined | undefined;
        }) & {
            authorizationList: viem.TransactionSerializableEIP7702["authorizationList"];
        } ? "eip7702" : never) | (request["type"] extends string | undefined ? Extract<request["type"], string> : never)>) ? T_12 extends "eip7702" ? viem.TransactionRequestEIP7702 : never : never : never)>> & {
            chainId?: number | undefined;
        }, (request["parameters"] extends readonly viem.PrepareTransactionRequestParameterType[] ? request["parameters"][number] : "type" | "chainId" | "gas" | "nonce" | "blobVersionedHashes" | "fees") extends infer T_13 ? T_13 extends (request["parameters"] extends readonly viem.PrepareTransactionRequestParameterType[] ? request["parameters"][number] : "type" | "chainId" | "gas" | "nonce" | "blobVersionedHashes" | "fees") ? T_13 extends "fees" ? "gasPrice" | "maxFeePerGas" | "maxPriorityFeePerGas" : T_13 : never : never> & (unknown extends request["kzg"] ? {} : Pick<request, "kzg">) extends infer T ? { [K in keyof T]: T[K]; } : never>;
        readContract: <const abi extends abitype.Abi | readonly unknown[], functionName extends viem.ContractFunctionName<abi, "pure" | "view">, const args extends viem.ContractFunctionArgs<abi, "pure" | "view", functionName>>(args: viem.ReadContractParameters<abi, functionName, args>) => Promise<viem.ReadContractReturnType<abi, functionName, args>>;
        sendRawTransaction: (args: viem.SendRawTransactionParameters) => Promise<viem.SendRawTransactionReturnType>;
        simulate: <const calls extends readonly unknown[]>(args: viem.SimulateBlocksParameters<calls>) => Promise<viem.SimulateBlocksReturnType<calls>>;
        simulateBlocks: <const calls extends readonly unknown[]>(args: viem.SimulateBlocksParameters<calls>) => Promise<viem.SimulateBlocksReturnType<calls>>;
        simulateCalls: <const calls extends readonly unknown[]>(args: viem.SimulateCallsParameters<calls>) => Promise<viem.SimulateCallsReturnType<calls>>;
        simulateContract: <const abi extends abitype.Abi | readonly unknown[], functionName extends viem.ContractFunctionName<abi, "payable" | "nonpayable">, const args_1 extends viem.ContractFunctionArgs<abi, "payable" | "nonpayable", functionName>, chainOverride extends Chain | undefined, accountOverride extends Account | abitype.Address | undefined = undefined>(args: viem.SimulateContractParameters<abi, functionName, args_1, Chain, chainOverride, accountOverride>) => Promise<viem.SimulateContractReturnType<abi, functionName, args_1, Chain, Account, chainOverride, accountOverride>>;
        verifyMessage: (args: viem.VerifyMessageActionParameters) => Promise<viem.VerifyMessageActionReturnType>;
        verifySiweMessage: (args: VerifySiweMessageParameters) => Promise<VerifySiweMessageReturnType>;
        verifyTypedData: (args: viem.VerifyTypedDataActionParameters) => Promise<viem.VerifyTypedDataActionReturnType>;
        uninstallFilter: (args: viem.UninstallFilterParameters) => Promise<viem.UninstallFilterReturnType>;
        waitForTransactionReceipt: (args: viem.WaitForTransactionReceiptParameters<Chain>) => Promise<viem.TransactionReceipt>;
        watchBlockNumber: (args: viem.WatchBlockNumberParameters) => viem.WatchBlockNumberReturnType;
        watchBlocks: <includeTransactions extends boolean = false, blockTag extends viem.BlockTag = "latest">(args: viem.WatchBlocksParameters<Transport, Chain, includeTransactions, blockTag>) => viem.WatchBlocksReturnType;
        watchContractEvent: <const abi extends abitype.Abi | readonly unknown[], eventName extends viem.ContractEventName<abi>, strict extends boolean | undefined = undefined>(args: viem.WatchContractEventParameters<abi, eventName, strict, Transport>) => viem.WatchContractEventReturnType;
        watchEvent: <const abiEvent extends abitype.AbiEvent | undefined = undefined, const abiEvents extends readonly abitype.AbiEvent[] | readonly unknown[] | undefined = abiEvent extends abitype.AbiEvent ? [abiEvent] : undefined, strict extends boolean | undefined = undefined>(args: viem.WatchEventParameters<abiEvent, abiEvents, strict, Transport>) => viem.WatchEventReturnType;
        watchPendingTransactions: (args: viem.WatchPendingTransactionsParameters<Transport>) => viem.WatchPendingTransactionsReturnType;
    } & viem.WalletActions<Chain, Account>>;
    /** Address of the account used to create this client */
    address: `0x${string}`;
    /** Contract addresses being used */
    contractAddresses: ChainAddresses;
    /**
     * Retrieves an attestation by its UID
     * @param uid - The unique identifier of the attestation
     * @returns The attestation data
     */
    getAttestation: (uid: `0x${string}`) => Promise<{
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
    }>;
    /**
     * Gets an attestation from a transaction hash
     * @param hash - The transaction hash
     * @returns The attestation event args
     */
    getAttestedEventFromTxHash: (hash: `0x${string}`) => Promise<{
        recipient: `0x${string}`;
        attester: `0x${string}`;
        uid: `0x${string}`;
        schemaUID: `0x${string}`;
    }>;
    /**
     * Waits for an escrow to be fulfilled
     * @param contractAddress - The address of the escrow contract
     * @param buyAttestation - The UID of the buy attestation
     * @returns Object containing payment, fulfillment and fulfiller details
     *
     * @example
     * ```ts
     * // Wait for fulfillment of an escrow
     * const fulfillment = await client.waitForFulfillment(
     *   contractAddresses.erc20EscrowObligation,
     *   escrow.attested.uid,
     * );
     * ```
     */
    waitForFulfillment: (contractAddress: `0x${string}`, buyAttestation: `0x${string}`, pollingInterval?: number) => Promise<{
        payment?: `0x${string}` | undefined;
        fulfillment?: `0x${string}` | undefined;
        fulfiller?: `0x${string}` | undefined;
    }>;
} & {
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
        encodeCommitTestsDemand: (demand: {
            oracle: `0x${string}`;
            testsCommitHash: string;
            testsCommand: string;
            testsCommitAlgo: number;
            hosts: string[];
        }) => `0x${string}`;
        decodeCommitTestsDemand: (demandData: `0x${string}`) => {
            oracle: `0x${string}`;
            testsCommitHash: string;
            testsCommand: string;
            testsCommitAlgo: number;
            hosts: readonly string[];
        };
        listenForArbitrationRequestsOnly: (oracle: `0x${string}`, arbitrationHandler: (obligation: `0x${string}`, oracle: `0x${string}`) => Promise<boolean>, pollingInterval?: number) => viem.WatchEventReturnType;
    };
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
        decodeEscrowObligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            amount: bigint;
        };
        decodePaymentObligation: (obligationData: `0x${string}`) => {
            token: `0x${string}`;
            amount: bigint;
            payee: `0x${string}`;
        };
        getEscrowSchema: () => Promise<`0x${string}`>;
        getPaymentSchema: () => Promise<`0x${string}`>;
        getEscrowObligation: (uid: `0x${string}`) => Promise<{
            data: {
                arbiter: `0x${string}`;
                demand: `0x${string}`;
                token: `0x${string}`;
                amount: bigint;
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
        getPaymentObligation: (uid: `0x${string}`) => Promise<{
            data: {
                token: `0x${string}`;
                amount: bigint;
                payee: `0x${string}`;
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
        decodeEscrowObligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            tokenId: bigint;
        } | {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            tokenId: bigint;
        };
        decodePaymentObligation: (obligationData: `0x${string}`) => {
            token: `0x${string}`;
            tokenId: bigint;
            payee: `0x${string}`;
        };
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
        decodeEscrowObligation: (obligationData: `0x${string}`) => {
            arbiter: `0x${string}`;
            demand: `0x${string}`;
            token: `0x${string}`;
            tokenId: bigint;
            amount: bigint;
        };
        decodePaymentObligation: (obligationData: `0x${string}`) => {
            token: `0x${string}`;
            tokenId: bigint;
            amount: bigint;
            payee: `0x${string}`;
        };
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
        } | {
            erc20Tokens: readonly `0x${string}`[];
            erc20Amounts: readonly bigint[];
            erc721Tokens: readonly `0x${string}`[];
            erc721TokenIds: readonly bigint[];
            erc1155Tokens: readonly `0x${string}`[];
            erc1155TokenIds: readonly bigint[];
            erc1155Amounts: readonly bigint[];
        };
        decodePaymentObligation: (obligationData: `0x${string}`) => {
            payee: `0x${string}`;
            erc20Tokens: readonly `0x${string}`[];
            erc20Amounts: readonly bigint[];
            erc721Tokens: readonly `0x${string}`[];
            erc721TokenIds: readonly bigint[];
            erc1155Tokens: readonly `0x${string}`[];
            erc1155TokenIds: readonly bigint[];
            erc1155Amounts: readonly bigint[];
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
    stringObligation: {
        encode: (data: {
            item: string;
        }) => `0x${string}`;
        decode: (obligationData: `0x${string}`) => {
            item: string;
        };
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
            data: {
                item: string;
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
    commitObligation: {
        encode: (data: CommitObligationData) => `0x${string}`;
        decode: (obligationData: `0x${string}`) => {
            hosts: readonly string[];
            commitHash: string;
            commitAlgo: number;
        };
        doObligation: (data: CommitObligationData, refUID?: `0x${string}`) => Promise<{
            hash: `0x${string}`;
            attested: any;
        }>;
        getSchema: () => Promise<`0x${string}`>;
        getObligationData: (uid: `0x${string}`) => Promise<{
            commitHash: string;
            commitAlgo: number;
            hosts: readonly string[];
        }>;
        getObligation: (uid: `0x${string}`) => Promise<{
            data: {
                hosts: readonly string[];
                commitHash: string;
                commitAlgo: number;
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
            arbitrate: (obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<T_2[key_1], abiParameterKind>; } : never) extends infer T_1 ? { [key in keyof T_1]: T_1[key]; } : never) => Promise<boolean | null>;
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
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_2 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_2]: abitype.AbiParameterToPrimitiveType<T_2[key_1], abiParameterKind>; } : never) extends infer T_1 ? { [key in keyof T_1]: T_1[key]; } : never;
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
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_4]: abitype.AbiParameterToPrimitiveType<T_4[key_1], abiParameterKind>; } : never) extends infer T_3 ? { [key in keyof T_3]: T_3[key]; } : never;
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
                obligation: ((T extends readonly abitype.AbiParameter[] ? T : abitype.AbiParameter[]) extends infer T_6 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_6]: abitype.AbiParameterToPrimitiveType<T_6[key_1], abiParameterKind>; } : never) extends infer T_5 ? { [key in keyof T_5]: T_5[key]; } : never;
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
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never) => Promise<boolean | null>;
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
                    obligation: ((ObligationData extends infer T_2 ? T_2 extends ObligationData ? T_2 extends readonly abitype.AbiParameter[] ? T_2 : abitype.AbiParameter[] : never : never) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never;
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
                    obligation: ((ObligationData extends infer T_5 ? T_5 extends ObligationData ? T_5 extends readonly abitype.AbiParameter[] ? T_5 : abitype.AbiParameter[] : never : never) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_4]: abitype.AbiParameterToPrimitiveType<T_4[key_1], abiParameterKind>; } : never) extends infer T_3 ? { [key in keyof T_3]: T_3[key]; } : never;
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
                    obligation: ((ObligationData extends infer T_8 ? T_8 extends ObligationData ? T_8 extends readonly abitype.AbiParameter[] ? T_8 : abitype.AbiParameter[] : never : never) extends infer T_7 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_7]: abitype.AbiParameterToPrimitiveType<T_7[key_1], abiParameterKind>; } : never) extends infer T_6 ? { [key in keyof T_6]: T_6[key]; } : never;
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
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never) => Promise<boolean | null>;
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
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_3]: abitype.AbiParameterToPrimitiveType<T_3[key_3], abiParameterKind>; } : never) extends infer T_2 ? { [key_2 in keyof T_2]: T_2[key_2]; } : never) => Promise<boolean | null>;
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
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never;
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_3]: abitype.AbiParameterToPrimitiveType<T_3[key_3], abiParameterKind>; } : never) extends infer T_2 ? { [key_2 in keyof T_2]: T_2[key_2]; } : never;
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
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_5 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_5]: abitype.AbiParameterToPrimitiveType<T_5[key_1], abiParameterKind>; } : never) extends infer T_4 ? { [key in keyof T_4]: T_4[key]; } : never;
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_7 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_7]: abitype.AbiParameterToPrimitiveType<T_7[key_3], abiParameterKind>; } : never) extends infer T_6 ? { [key_2 in keyof T_6]: T_6[key_2]; } : never;
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
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_9 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_9]: abitype.AbiParameterToPrimitiveType<T_9[key_3], abiParameterKind>; } : never) extends infer T_8 ? { [key_2 in keyof T_8]: T_8[key_2]; } : never;
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
                obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_11 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_11]: abitype.AbiParameterToPrimitiveType<T_11[key_1], abiParameterKind>; } : never) extends infer T_10 ? { [key in keyof T_10]: T_10[key]; } : never;
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
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_3]: abitype.AbiParameterToPrimitiveType<T_3[key_3], abiParameterKind>; } : never) extends infer T_2 ? { [key_2 in keyof T_2]: T_2[key_2]; } : never) => Promise<boolean | null>;
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
                    obligation: ((ObligationData extends infer T_2 ? T_2 extends ObligationData ? T_2 extends readonly abitype.AbiParameter[] ? T_2 : abitype.AbiParameter[] : never : never) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never;
                    demand: ((DemandData extends infer T_5 ? T_5 extends DemandData ? T_5 extends readonly abitype.AbiParameter[] ? T_5 : abitype.AbiParameter[] : never : never) extends infer T_4 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_4]: abitype.AbiParameterToPrimitiveType<T_4[key_3], abiParameterKind>; } : never) extends infer T_3 ? { [key_2 in keyof T_3]: T_3[key_2]; } : never;
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
                    obligation: ((ObligationData extends infer T_8 ? T_8 extends ObligationData ? T_8 extends readonly abitype.AbiParameter[] ? T_8 : abitype.AbiParameter[] : never : never) extends infer T_7 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_7]: abitype.AbiParameterToPrimitiveType<T_7[key_1], abiParameterKind>; } : never) extends infer T_6 ? { [key in keyof T_6]: T_6[key]; } : never;
                    demand: ((DemandData extends infer T_11 ? T_11 extends DemandData ? T_11 extends readonly abitype.AbiParameter[] ? T_11 : abitype.AbiParameter[] : never : never) extends infer T_10 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_10]: abitype.AbiParameterToPrimitiveType<T_10[key_3], abiParameterKind>; } : never) extends infer T_9 ? { [key_2 in keyof T_9]: T_9[key_2]; } : never;
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
                    demand: ((DemandData extends infer T_14 ? T_14 extends DemandData ? T_14 extends readonly abitype.AbiParameter[] ? T_14 : abitype.AbiParameter[] : never : never) extends infer T_13 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_13]: abitype.AbiParameterToPrimitiveType<T_13[key_3], abiParameterKind>; } : never) extends infer T_12 ? { [key_2 in keyof T_12]: T_12[key_2]; } : never;
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
                    obligation: ((ObligationData extends infer T_17 ? T_17 extends ObligationData ? T_17 extends readonly abitype.AbiParameter[] ? T_17 : abitype.AbiParameter[] : never : never) extends infer T_16 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_16]: abitype.AbiParameterToPrimitiveType<T_16[key_1], abiParameterKind>; } : never) extends infer T_15 ? { [key in keyof T_15]: T_15[key]; } : never;
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
            arbitrate: (obligation: ((ObligationData extends readonly abitype.AbiParameter[] ? ObligationData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never, demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_3 extends readonly abitype.AbiParameter[] ? { [key_3 in keyof T_3]: abitype.AbiParameterToPrimitiveType<T_3[key_3], abiParameterKind>; } : never) extends infer T_2 ? { [key_2 in keyof T_2]: T_2[key_2]; } : never) => Promise<boolean | null>;
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
                demand: ((DemandData extends readonly abitype.AbiParameter[] ? DemandData : abitype.AbiParameter[]) extends infer T_1 extends readonly abitype.AbiParameter[] ? { [key_1 in keyof T_1]: abitype.AbiParameterToPrimitiveType<T_1[key_1], abiParameterKind>; } : never) extends infer T ? { [key in keyof T]: T[key]; } : never;
            }[];
            unwatch: () => void;
        }>;
    };
};

type AlkahestTestActions = ReturnType<ReturnType<typeof createTokenTestExtension>>;
declare function createTokenTestExtension<C extends Client & PublicActions>(): (client: C) => {
    getErc20Balance(token: Omit<Erc20, "value">, owner: `0x${string}`): Promise<bigint>;
    getErc721Owner(token: Erc721): Promise<`0x${string}`>;
    getErc1155Balance(token: Omit<Erc1155, "value">, owner: `0x${string}`): Promise<bigint>;
};

type TestContext = {
    anvil: ReturnType<typeof createAnvil>;
    testClient: TestClient & WalletActions & PublicActions & AlkahestTestActions;
    anvilInitState?: `0x${string}`;
    alice: `0x${string}`;
    bob: `0x${string}`;
    aliceClient: ReturnType<typeof makeClient>;
    bobClient: ReturnType<typeof makeClient>;
    aliceClientWs: ReturnType<typeof makeClient>;
    bobClientWs: ReturnType<typeof makeClient>;
    addresses: {
        eas: `0x${string}`;
        easSchemaRegistry: `0x${string}`;
        trivialArbiter: `0x${string}`;
        trustedPartyArbiter: `0x${string}`;
        trustedOracleArbiter: `0x${string}`;
        commitTestsArbiter: `0x${string}`;
        specificAttestationArbiter: `0x${string}`;
        intrinsicsArbiter: `0x${string}`;
        intrinsicsArbiter2: `0x${string}`;
        anyArbiter: `0x${string}`;
        allArbiter: `0x${string}`;
        erc20EscrowObligation: `0x${string}`;
        erc20PaymentObligation: `0x${string}`;
        erc20BarterUtils: `0x${string}`;
        erc721EscrowObligation: `0x${string}`;
        erc721PaymentObligation: `0x${string}`;
        erc721BarterUtils: `0x${string}`;
        erc1155EscrowObligation: `0x${string}`;
        erc1155PaymentObligation: `0x${string}`;
        erc1155BarterUtils: `0x${string}`;
        tokenBundleEscrowObligation: `0x${string}`;
        tokenBundlePaymentObligation: `0x${string}`;
        tokenBundleBarterUtils: `0x${string}`;
        attestationEscrowObligation: `0x${string}`;
        attestationEscrowObligation2: `0x${string}`;
        attestationBarterUtils: `0x${string}`;
        stringObligation: `0x${string}`;
        commitObligation: `0x${string}`;
    };
    mockAddresses: {
        erc20A: `0x${string}`;
        erc20B: `0x${string}`;
        erc721A: `0x${string}`;
        erc721B: `0x${string}`;
        erc1155A: `0x${string}`;
        erc1155B: `0x${string}`;
    };
};
/**
 * Sets up a complete test environment for Alkahest tests
 *
 * This function:
 * 1. Launches an Anvil instance
 * 2. Sets up test accounts with ETH
 * 3. Deploys all core contracts (EAS, obligations, arbiters, etc.)
 * 4. Deploys mock tokens for testing
 * 5. Distributes mock tokens to test accounts
 * 6. Creates Alkahest clients for each test account
 *
 * @returns TestContext object with all necessary test resources
 */
declare function setupTestEnvironment(): Promise<TestContext>;
/**
 * Tears down the test environment
 * @param context The test context to tear down
 */
declare function teardownTestEnvironment(context: TestContext): Promise<void>;

export { type TestContext, setupTestEnvironment, teardownTestEnvironment };
