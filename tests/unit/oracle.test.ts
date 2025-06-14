import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import { encodeAbiParameters, parseAbiParameters } from "viem";
import {
  setupTestEnvironment,
  teardownTestEnvironment,
  type TestContext,
} from "../utils/setup";

let testContext: TestContext;

beforeAll(async () => {
  testContext = await setupTestEnvironment();
});

beforeEach(async () => {
  // Reset to initial state before each test
  if (testContext.anvilInitState) {
    await testContext.testClient.loadState({
      state: testContext.anvilInitState,
    });
  }
});

afterAll(async () => {
  // Clean up
  await teardownTestEnvironment(testContext);
});

test("trivialArbitratePast", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  const decisions = await testContext.bobClient.oracle.arbitratePast({
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement) => true,
  });

  decisions.decisions.forEach(($) => expect($?.decision).toBe(true));

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment.uid,
  );

  expect(collectionHash).toBeTruthy();
});

test("trivialListenAndArbitrate", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { unwatch } = await testContext.bobClient.oracle.listenAndArbitrate({
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement) => true,
    onAfterArbitrate: async (decision) => {
      expect(decision?.attestation.uid).toEqual(fulfillment.uid);
      expect(decision?.statement[0].item).toEqual("foo");
      expect(decision?.decision).toBe(true);
    },
    pollingInterval: 50,
  });

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  await Bun.sleep(100);
  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment.uid,
  );

  expect(collectionHash).toBeTruthy();

  unwatch();
});

test("conditionalArbitratePast", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment1 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "good",
      escrow.uid,
    );

  const { attested: fulfillment2 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "bad",
      escrow.uid,
    );

  const decisions = await testContext.bobClient.oracle.arbitratePast({
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement) => _statement[0].item === "good",
  });

  decisions.decisions.forEach(($) =>
    expect($?.decision).toBe($?.statement[0].item === "good"),
  );

  const failedCollection = testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment2.uid,
  );
  expect(async () => await failedCollection).toThrow();

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment1.uid,
  );

  expect(collectionHash).toBeTruthy();
});

test("conditionalListenAndArbitrate", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { unwatch } = await testContext.bobClient.oracle.listenAndArbitrate({
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement) => _statement[0].item === "good",
    onAfterArbitrate: async (decision) => {
      expect(decision?.decision).toBe(decision?.statement[0].item === "good");
    },
    pollingInterval: 50,
  });

  const { attested: fulfillment1 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "good",
      escrow.uid,
    );

  const { attested: fulfillment2 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "bad",
      escrow.uid,
    );

  await Bun.sleep(100);
  const failedCollection = testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment2.uid,
  );
  expect(async () => await failedCollection).toThrow();

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment1.uid,
  );
  expect(collectionHash).toBeTruthy();

  unwatch();
});

test("trivialArbitratePastEscrow", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  const decisions = await testContext.bobClient.oracle.arbitratePastForEscrow({
    escrow: {
      attester: testContext.addresses.erc20EscrowObligation,
      demandAbi: parseAbiParameters("(string mockDemand)"),
    },
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement, _demand) => true,
  });

  decisions.decisions.forEach(($) => expect($?.decision).toBe(true));

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment.uid,
  );

  expect(collectionHash).toBeTruthy();
});

test("trivialListenAndArbitrateEscrow", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { unwatch } =
    await testContext.bobClient.oracle.listenAndArbitrateForEscrow({
      escrow: {
        attester: testContext.addresses.erc20EscrowObligation,
        demandAbi: parseAbiParameters("(string mockDemand)"),
      },
      fulfillment: {
        attester: testContext.addresses.stringObligation,
        statementAbi: parseAbiParameters("(string item)"),
      },
      arbitrate: async (_statement, _demand) => true,
      onAfterArbitrate: async (decision) => {
        expect(decision?.attestation.uid).toEqual(fulfillment.uid);
        expect(decision?.statement[0].item).toEqual("foo");
        expect(decision?.decision).toBe(true);
      },
      pollingInterval: 50,
    });

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  await Bun.sleep(100);
  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment.uid,
  );

  expect(collectionHash).toBeTruthy();

  unwatch();
});

test("conditionalArbitratePastEscrow", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment1 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  const { attested: fulfillment2 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "bar",
      escrow.uid,
    );

  const decisions = await testContext.bobClient.oracle.arbitratePastForEscrow({
    escrow: {
      attester: testContext.addresses.erc20EscrowObligation,
      demandAbi: parseAbiParameters("(string mockDemand)"),
    },
    fulfillment: {
      attester: testContext.addresses.stringObligation,
      statementAbi: parseAbiParameters("(string item)"),
    },
    arbitrate: async (_statement, _demand) =>
      _statement[0].item === _demand[0].mockDemand,
  });

  decisions.decisions.forEach(($) =>
    expect($!.demand[0].mockDemand === $!.statement[0].item).toBe($!.decision !== null ? $!.decision : false),
  );

  const failedCollection = testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment2.uid,
  );
  expect(async () => await failedCollection).toThrow();

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment1.uid,
  );

  expect(collectionHash).toBeTruthy();
});

test("conditionalListenAndArbitrateEscrow", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { unwatch } =
    await testContext.bobClient.oracle.listenAndArbitrateForEscrow({
      escrow: {
        attester: testContext.addresses.erc20EscrowObligation,
        demandAbi: parseAbiParameters("(string mockDemand)"),
      },
      fulfillment: {
        attester: testContext.addresses.stringObligation,
        statementAbi: parseAbiParameters("(string item)"),
      },
      arbitrate: async (_statement, _demand) =>
        _statement[0].item === _demand[0].mockDemand,
      onAfterArbitrate: async (decision) => {
        expect(decision?.decision).toBe(
          decision?.statement[0].item === decision?.demand[0].mockDemand,
        );
      },
      pollingInterval: 50,
    });

  const { attested: fulfillment1 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  const { attested: fulfillment2 } =
    await testContext.bobClient.stringObligation.makeStatement(
      "bar",
      escrow.uid,
    );

  await Bun.sleep(100);
  const failedCollection = testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment2.uid,
  );
  expect(async () => await failedCollection).toThrow();

  const collectionHash = await testContext.bobClient.erc20.collectPayment(
    escrow.uid,
    fulfillment1.uid,
  );
  expect(collectionHash).toBeTruthy();

  unwatch();
});

test("arbitratePast with skipAlreadyArbitrated option", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  // First arbitration should succeed
  const { decisions: firstDecisions } =
    await testContext.bobClient.oracle.arbitratePast({
      fulfillment: {
        statementAbi: parseAbiParameters("(string item)"),
        attester: testContext.addresses.stringObligation,
      },
      arbitrate: async (statement) => {
        return statement[0].item === "foo";
      },
      skipAlreadyArbitrated: false, // Explicitly set to false
    });

  expect(firstDecisions.length).toBe(1);
  expect(firstDecisions[0]?.decision).toBe(true);

  // Wait for the transaction to be confirmed
  const firstDecision = firstDecisions[0];
  if (firstDecision && 'hash' in firstDecision && firstDecision.hash) {
    await testContext.testClient.waitForTransactionReceipt({
      hash: firstDecision.hash,
    });
  } else {
    throw new Error("Expected first decision to have a hash");
  }

  // Second arbitration with skipAlreadyArbitrated: false should attempt to arbitrate again
  const { decisions: secondDecisions } =
    await testContext.bobClient.oracle.arbitratePast({
      fulfillment: {
        statementAbi: parseAbiParameters("(string item)"),
        attester: testContext.addresses.stringObligation,
      },
      arbitrate: async (statement) => {
        return statement[0].item === "foo";
      },
      skipAlreadyArbitrated: false,
    });

  expect(secondDecisions.length).toBe(1);

  // Third arbitration with skipAlreadyArbitrated: true should skip re-arbitration
  const { decisions: thirdDecisions } =
    await testContext.bobClient.oracle.arbitratePast({
      fulfillment: {
        statementAbi: parseAbiParameters("(string item)"),
        attester: testContext.addresses.stringObligation,
      },
      arbitrate: async (statement) => {
        return statement[0].item === "foo";
      },
      skipAlreadyArbitrated: true,
    });

  expect(thirdDecisions.length).toBe(0); // Should skip already arbitrated fulfillments
});

test("arbitratePastForEscrow with skipAlreadyArbitrated option", async () => {
  const arbiter = testContext.addresses.trustedOracleArbiter;
  const demand = testContext.aliceClient.arbiters.encodeTrustedOracleDemand({
    oracle: testContext.bob,
    data: encodeAbiParameters(parseAbiParameters("(string mockDemand)"), [
      { mockDemand: "foo" },
    ]),
  });

  const { attested: escrow } =
    await testContext.aliceClient.erc20.permitAndBuyWithErc20(
      {
        address: testContext.mockAddresses.erc20A,
        value: 10n,
      },
      { arbiter, demand },
      0n,
    );

  const { attested: fulfillment } =
    await testContext.bobClient.stringObligation.makeStatement(
      "foo",
      escrow.uid,
    );

  // First arbitration should succeed
  const { decisions: firstDecisions } =
    await testContext.bobClient.oracle.arbitratePastForEscrow({
      escrow: {
        attester: testContext.addresses.erc20EscrowObligation,
        demandAbi: parseAbiParameters("(string mockDemand)"),
      },
      fulfillment: {
        attester: testContext.addresses.stringObligation,
        statementAbi: parseAbiParameters("(string item)"),
      },
      arbitrate: async (statement, demand) => {
        return statement[0].item === demand[0].mockDemand;
      },
      skipAlreadyArbitrated: false,
    });

  expect(firstDecisions.length).toBe(1);
  expect(firstDecisions[0]?.decision).toBe(true);

  // Wait for the transaction to be confirmed
  await testContext.testClient.waitForTransactionReceipt({
    hash: firstDecisions[0]?.hash!,
  });

  // Second arbitration with skipAlreadyArbitrated: true should skip re-arbitration
  const { decisions: secondDecisions } =
    await testContext.bobClient.oracle.arbitratePastForEscrow({
      escrow: {
        attester: testContext.addresses.erc20EscrowObligation,
        demandAbi: parseAbiParameters("(string mockDemand)"),
      },
      fulfillment: {
        attester: testContext.addresses.stringObligation,
        statementAbi: parseAbiParameters("(string item)"),
      },
      arbitrate: async (statement, demand) => {
        return statement[0].item === demand[0].mockDemand;
      },
      skipAlreadyArbitrated: true,
    });

  expect(secondDecisions.length).toBe(0); // Should skip already arbitrated fulfillments
});
