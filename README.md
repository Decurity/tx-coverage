# tx-coverage

Reveal unused code of a live smart contract by collecting coverage from historical transactions.

## Installtion

```bash
cargo install --path .
```

## Usage

To use `tx-coverage` you need a Foundry project and an address of a deployed smart contract. You can initialize a new Foundry project from any address by using `cast etherscan-source` command to download the source code tree from Etherscan and running `forge init`. You will also need to use exactly the same compiler settings as the one used to compile the smart contract, otherwise the bytecode source maps will not match coverage hit maps. Alternatively you can use `forge clone` from [EtherDebug](https://github.com/EtherDebug/foundry) to bootstrap the project with the correct compiler settings.

To retrieve the transaction hashes to collect coverage from, `tx-coverage` uses [Dune](https://dune.com/) data (you will need a free API key). Specifically, it fetches calls to the target address only with the unique calldata, which reduces the number of transactions to replay, although some traces with the same calldata may result in different execution paths.

```bash
tx-coverage 0x2b4864c2f2a2c275c6c66b90a2ae6be9fa9cbe47
```

```
[⠊] Compiling...
[⠒] Compiling 1 files with 0.8.23
[⠑] Solc 0.8.23 finished in 491.93ms
Compiler run successful!
Fetching transaction hashes for address: 0x2b4864c2f2a2c275c6c66b90a2ae6be9fa9cbe47
Found 23 transaction hashes
⠓ [00:00:50] [######################################################################] 23/23 tx (0.0s)
Wrote LCOV report.
| File             | % Lines         | % Statements    | % Branches      | % Funcs        |
|------------------|-----------------|-----------------|-----------------|----------------|
| src/Contract.sol | 24.69% (59/239) | 20.69% (66/319) | 15.00% (18/120) | 26.42% (14/53) |
| Total            | 24.69% (59/239) | 20.69% (66/319) | 15.00% (18/120) | 26.42% (14/53) |
```

The output is an LCOV report that can be visualized with tools like [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters). In VSCode you can see which lines were never executed and potentially contain bugs.

