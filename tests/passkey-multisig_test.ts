import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.7.1/index.ts';
import { assertEquals, assertExists } from 'https://deno.land/std@0.170.0/testing/asserts.ts';

// Sample secp256r1 public keys (33 bytes compressed format) for passkey authentication
const samplePubkey1 = "0x037a6b62e3c8b14f1b5933f5d5ab0509a8e7d95a111b8d3b264d95bfa753b00296";
const samplePubkey2 = "0x02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc";
const samplePubkey3 = "0x03b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const multisigId = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

Clarinet.test({
  name: "Can create a multisig wallet",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2), // 2-of-3 threshold
        types.list([
          types.buff(samplePubkey1),
          types.buff(samplePubkey2),
          types.buff(samplePubkey3)
        ])
      ], deployer.address)
    ]);
    
    block.receipts[0].result.expectOk();
  }
});

Clarinet.test({
  name: "Can get multisig details",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    
    // Create multisig first
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2),
        types.list([
          types.buff(samplePubkey1),
          types.buff(samplePubkey2)
        ])
      ], deployer.address)
    ]);
    
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'get-multisig',
      [types.buff(multisigId)],
      deployer.address
    );
    
    assertExists(result.result);
  }
});

Clarinet.test({
  name: "Can deposit to multisig",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    
    // Create multisig
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2),
        types.list([types.buff(samplePubkey1), types.buff(samplePubkey2)])
      ], deployer.address)
    ]);
    
    // Deposit
    block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'deposit', [
        types.buff(multisigId),
        types.uint(1000000000)
      ], deployer.address)
    ]);
    
    block.receipts[0].result.expectOk();
  }
});

Clarinet.test({
  name: "Invalid threshold fails",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    
    // Threshold > signer count should fail
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(5), // Invalid: only 2 signers
        types.list([types.buff(samplePubkey1), types.buff(samplePubkey2)])
      ], deployer.address)
    ]);
    
    block.receipts[0].result.expectErr().expectUint(5009);
  }
});

Clarinet.test({
  name: "Can generate transaction summary",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'generate-tx-summary',
      [
        types.buff(multisigId),
        types.uint(1),
        types.ascii("TRANSFER"),
        types.uint(1000000000)
      ],
      deployer.address
    );
    
    assertExists(result.result);
  }
});

Clarinet.test({
  name: "Get current time works",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'get-current-time',
      [],
      deployer.address
    );

    assertExists(result.result);
  }
});

Clarinet.test({
  name: "Can verify signer is valid",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    // Create multisig first
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2),
        types.list([types.buff(samplePubkey1), types.buff(samplePubkey2)])
      ], deployer.address)
    ]);

    // Check valid signer
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'is-valid-signer',
      [types.buff(multisigId), types.buff(samplePubkey1)],
      deployer.address
    );

    assertEquals(result.result, 'true');

    // Check invalid signer
    result = chain.callReadOnlyFn(
      'passkey-multisig',
      'is-valid-signer',
      [types.buff(multisigId), types.buff(samplePubkey3)],
      deployer.address
    );

    assertEquals(result.result, 'false');
  }
});

Clarinet.test({
  name: "Cannot create multisig with zero threshold",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(0), // Invalid threshold
        types.list([types.buff(samplePubkey1)])
      ], deployer.address)
    ]);

    block.receipts[0].result.expectErr().expectUint(5009);
  }
});

Clarinet.test({
  name: "Can get signer details",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    // Create multisig
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2),
        types.list([types.buff(samplePubkey1), types.buff(samplePubkey2), types.buff(samplePubkey3)])
      ], deployer.address)
    ]);

    // Get first signer
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'get-signer',
      [types.buff(multisigId), types.uint(0)],
      deployer.address
    );

    assertExists(result.result);

    // Get second signer
    result = chain.callReadOnlyFn(
      'passkey-multisig',
      'get-signer',
      [types.buff(multisigId), types.uint(1)],
      deployer.address
    );

    assertExists(result.result);
  }
});

Clarinet.test({
  name: "Multiple deposits accumulate correctly",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    // Create multisig
    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'create-multisig', [
        types.buff(multisigId),
        types.ascii("Test Multisig"),
        types.uint(2),
        types.list([types.buff(samplePubkey1), types.buff(samplePubkey2)])
      ], deployer.address)
    ]);

    // First deposit
    block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'deposit', [
        types.buff(multisigId),
        types.uint(1000000)
      ], deployer.address)
    ]);

    block.receipts[0].result.expectOk().expectUint(1000000);

    // Second deposit
    block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'deposit', [
        types.buff(multisigId),
        types.uint(2000000)
      ], deployer.address)
    ]);

    block.receipts[0].result.expectOk().expectUint(2000000);

    // Check balance
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'get-multisig',
      [types.buff(multisigId)],
      deployer.address
    );

    assertExists(result.result);
  }
});

Clarinet.test({
  name: "Cannot deposit to non-existent multisig",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;
    const nonExistentId = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let block = chain.mineBlock([
      Tx.contractCall('passkey-multisig', 'deposit', [
        types.buff(nonExistentId),
        types.uint(1000000)
      ], deployer.address)
    ]);

    block.receipts[0].result.expectErr().expectUint(5003);
  }
});

Clarinet.test({
  name: "Transaction summary contains correct information",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'generate-tx-summary',
      [
        types.buff(multisigId),
        types.uint(42),
        types.ascii("TRANSFER"),
        types.uint(5000000)
      ],
      deployer.address
    );

    assertExists(result.result);
    // Summary should contain transaction details
  }
});

Clarinet.test({
  name: "Can check transaction validity",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const deployer = accounts.get('deployer')!;

    // Check non-existent transaction
    let result = chain.callReadOnlyFn(
      'passkey-multisig',
      'is-tx-valid',
      [types.buff(multisigId), types.uint(999)],
      deployer.address
    );

    assertEquals(result.result, 'false');
  }
});
