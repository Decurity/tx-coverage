#[macro_use]
extern crate tracing;

use forge::revm::primitives::{alloy_primitives::{Address, Bytes, U256}, FixedBytes};
use alloy_provider::Provider;
use forge::revm::primitives::EnvWithHandlerCfg;
use clap::Parser;
use eyre::{Context, Result};
use forge::{
    coverage::{
        analysis::SourceAnalyzer, anchors::find_anchors, ContractId,
        CoverageReport, CoverageReporter, ItemAnchor, LcovReporter, SummaryReporter,
    },
    revm::primitives::SpecId,
    utils::IcPcMap,
    MultiContractRunnerBuilder,
};
use foundry_cli::{
    handler, init_progress, opts::RpcOpts, update_progress, utils
};
use foundry_common::{compile::ProjectCompiler, fs, is_known_system_sender, SYSTEM_TRANSACTION_TYPE};
use foundry_compilers::{
    artifacts::{contract::CompactContractBytecode, Ast, CompactBytecode, CompactDeployedBytecode},
    sourcemap::SourceMap,
    Artifact, EvmVersion, ProjectCompileOutput,
};
use foundry_config::{find_project_root_path, Config};

use foundry_evm::{
    executors::TracingExecutor,
    opts::EvmOpts,
    utils::configure_tx_env,
};
use rustc_hash::FxHashMap;
use semver::Version;
use std::collections::HashMap;
use serde::Deserialize;
use duners::{client::DuneClient, parameters::Parameter};

/// A map, keyed by contract ID, to a tuple of the deployment source map and the runtime source map.
type SourceMaps = HashMap<ContractId, (SourceMap, SourceMap)>;

#[derive(Deserialize, Debug, PartialEq)]
struct ResultStruct {
    tx_hash: String
}

/// CLI arguments for `tx-coverage`.
#[derive(Clone, Debug, Parser)]
pub struct TxCoverage {
    /// The contract's address.
    address: String,

    /// Dune API key
    #[arg(long, short, env = "DUNE_API_KEY")]
    dune_api_key: String,

    /// The RPC endpoint
    #[arg(long, short, env = "ETH_RPC_URL")]
    rpc_url: String,

    /// The maximum number of transactions to fetch from Dune
    /// default value: 100
    #[arg(long, short)]
    tx_limit: Option<usize>,

    /// The EVM version to use.
    ///
    /// Overrides the version specified in the config.
    #[arg(long)]
    evm_version: Option<EvmVersion>,

    /// Sets the number of assumed available compute units per second for this provider
    ///
    /// default value: 330
    ///
    /// See also, https://docs.alchemy.com/reference/compute-units#what-are-cups-compute-units-per-second
    #[arg(long, alias = "cups", value_name = "CUPS")]
    pub compute_units_per_second: Option<u64>,

    /// Disables rate limiting for this node's provider.
    ///
    /// default value: false
    ///
    /// See also, https://docs.alchemy.com/reference/compute-units#what-are-cups-compute-units-per-second
    #[arg(long, value_name = "NO_RATE_LIMITS", visible_alias = "no-rpc-rate-limit")]
    pub no_rate_limit: bool,
}

impl TxCoverage {
    /// Collects code coverage by replaying historical onchain transactions.
    pub async fn run(self) -> Result<()> {
        let chain_id_to_dune_table: HashMap<u64, String> = vec![
            (1, "ethereum".to_string()),
            (56, "bnb".to_string()),
            (42161, "arbitrum".to_string()),
            (10, "optimism".to_string()),
            (43114, "avalanche".to_string()),
            (250, "fantom".to_string()),
            (137, "polygon".to_string()),
        ].into_iter().collect();
        let rpc = RpcOpts{url: Some(self.rpc_url), flashbots: false, jwt_secret: None};
        let figment =
            Config::figment_with_root(find_project_root_path(None).unwrap()).merge(rpc);
        let evm_opts = figment.extract::<EvmOpts>()?;
        let mut config = Config::try_from(figment)?.sanitized();
        config.ast = true;
        let chain_id: u64 = evm_opts.get_chain_id();

        let compute_units_per_second =
            if self.no_rate_limit { Some(u64::MAX) } else { self.compute_units_per_second };

        let provider = foundry_common::provider::alloy::ProviderBuilder::new(
            &config.get_rpc_url_or_localhost_http()?,
        )
        .compute_units_per_second_opt(compute_units_per_second)
        .build()?;

        let project = config.ephemeral_no_artifacts_project()?;
        
        let output = ProjectCompiler::default()
            .compile(&project)?
            .with_stripped_file_prefixes(project.root());
        let mut report = prepare(&config, output.clone())?;
        debug!("Source maps {:?}", report.source_maps.len());
        
        let dune = DuneClient::new(&self.dune_api_key);
        println!("Fetching transaction hashes for address: {}", self.address);
        let results = dune.refresh::<ResultStruct>(
            3624749,
            Some(vec![
                Parameter::text("address", &self.address),
                Parameter::text("network", chain_id_to_dune_table.get(&chain_id).unwrap_or(&"ethereum".to_string())),
                Parameter::text("limit", &self.tx_limit.unwrap_or(100).to_string())
            ]), 
            None).await;
            let tx_hashes: Vec<String> = match results {
                Ok(response) => response.get_rows().iter().map(|result| result.tx_hash.clone()).collect(),
                Err(e) => return Err(eyre::eyre!("Dune request failed: {:?}", e)),
            };

        if tx_hashes.is_empty() {
            return Err(eyre::eyre!("No transaction hashes found"));
        } else {
            println!("Found {} transaction hashes", tx_hashes.len());
        }

        let root = project.paths.root.clone();

        let progress = init_progress!(tx_hashes, "tx");
        progress.set_position(0);

        for (idx, tx_hash) in tx_hashes.into_iter().enumerate() {
            let tx_hash: FixedBytes<32> = tx_hash.parse().wrap_err("invalid tx hash")?;

            let tx = provider
            .get_transaction_by_hash(tx_hash)
            .await
            .wrap_err_with(|| format!("tx not found: {:?}", tx_hash))?;

            // check if the tx is a system transaction
            if is_known_system_sender(tx.from) || tx.transaction_type == Some(SYSTEM_TRANSACTION_TYPE)
            {
                return Err(eyre::eyre!(
                    "{:?} is a system transaction.\nReplaying system transactions is currently not supported.",
                    tx.hash
                ));
            }

            let tx_block_number =
                tx.block_number.ok_or_else(|| eyre::eyre!("tx may still be pending: {:?}", tx_hash))?;

            // fetch the block the transaction was mined in
            let block = provider.get_block(tx_block_number.into(), true).await?;

            // we need to fork off the parent block
            config.fork_block_number = Some(tx_block_number - 1);

            let (mut env, fork, _) = TracingExecutor::get_fork_material(&config, evm_opts.clone()).await?;

            let runner = MultiContractRunnerBuilder::default()
            .set_coverage(true)
            .build(&root, output.clone(), env.clone(), evm_opts.clone())?;

            let known_contracts = runner.known_contracts.clone();

            let mut evm_version = self.evm_version;

            env.block.number = U256::from(tx_block_number);

            if let Some(block) = &block {
                env.block.timestamp = U256::from(block.header.timestamp);
                env.block.coinbase = block.header.miner;
                env.block.difficulty = block.header.difficulty;
                env.block.prevrandao = Some(block.header.mix_hash.unwrap_or_default());
                env.block.basefee = U256::from(block.header.base_fee_per_gas.unwrap_or_default());
                env.block.gas_limit = U256::from(block.header.gas_limit);

                // TODO: we need a smarter way to map the block to the corresponding evm_version for
                // commonly used chains
                if evm_version.is_none() {
                    // if the block has the excess_blob_gas field, we assume it's a Cancun block
                    if block.header.excess_blob_gas.is_some() {
                        evm_version = Some(EvmVersion::Cancun);
                    }
                }
            }

            let mut executor = TracingExecutor::new(env.clone(), fork, evm_version, false);
            executor.inspector.collect_coverage(true);
            let mut env =
                EnvWithHandlerCfg::new_with_spec_id(Box::new(env.clone()), executor.spec_id());
            // Execute our transaction
            configure_tx_env(&mut env, &tx);

            trace!(tx=?tx.hash, to=?tx.to, "executing call transaction");
            let raw_result = executor.commit_tx_with_env(env)?;
            if let Some(ref hitmaps) = raw_result.coverage {
                debug!("Length of hitmaps: {}", hitmaps.len());
                
                let hit_data = hitmaps.clone().0.into_values().filter_map(|map| {
                    Some((known_contracts.find_by_code(map.bytecode.as_ref())?.0, map))
                });
                
                for (artifact_id, hits) in hit_data {
                    debug!("Artifact ID: {:?}", artifact_id);
                    debug!("Length of hits: {}", hits.hits.len());
                    if let Some(source_id) = report.get_source_id(
                        artifact_id.version.clone(),
                        artifact_id.source.to_string_lossy().to_string(),
                    ) {
                        let source_id = *source_id;
                        report.add_hit_map(
                            &ContractId {
                                version: artifact_id.version.clone(),
                                source_id,
                                contract_name: artifact_id.name.clone(),
                            },
                            &hits,
                        )?;
                        debug!("Added hitmap: {:?}", source_id);
                    }
                }
            }
            update_progress!(progress, idx);
        };
        let _ = LcovReporter::new(&mut fs::create_file(root.join("lcov.info"))?).report(&report);
        let _ = SummaryReporter::default().report(&report);
        Ok(())
    }
}

#[instrument(name = "prepare", skip_all)]
fn prepare(config: &Config, output: ProjectCompileOutput) -> Result<CoverageReport> {
    let project_paths = config.project_paths();

    // Extract artifacts
    let (artifacts, sources) = output.into_artifacts_with_sources();
    let mut report = CoverageReport::default();

    // Collect ASTs and sources
    let mut versioned_asts: HashMap<Version, FxHashMap<usize, Ast>> = HashMap::new();
    let mut versioned_sources: HashMap<Version, FxHashMap<usize, String>> = HashMap::new();
    for (path, mut source_file, version) in sources.into_sources_with_version() {
        report.add_source(version.clone(), source_file.id as usize, path.clone());
        debug!("Added source: {:?}", path);
        // Filter out dependencies
        if project_paths.has_library_ancestor(std::path::Path::new(&path)) {
            continue
        }

        debug!("Source File: {:?}", source_file.id);
        if let Some(ast) = source_file.ast.take() {            
            versioned_asts
                .entry(version.clone())
                .or_default()
                .insert(source_file.id as usize, ast);

            let file = project_paths.root.join(&path);
            trace!(root=?project_paths.root, ?file, "reading source file");

            versioned_sources.entry(version.clone()).or_default().insert(
                source_file.id as usize,
                fs::read_to_string(&file)
                    .wrap_err("Could not read source code for analysis")?,
            );
        }
    }

    // Get source maps and bytecodes
    let (source_maps, bytecodes): (SourceMaps, HashMap<ContractId, (Bytes, Bytes)>) = artifacts
        .into_iter()
        .map(|(id, artifact)| (id, CompactContractBytecode::from(artifact)))
        .filter_map(|(id, artifact)| {
            let contract_id = ContractId {
                version: id.version.clone(),
                source_id: *report
                    .get_source_id(id.version, id.source.to_string_lossy().to_string())?,
                contract_name: id.name,
            };
            let source_maps = (
                contract_id.clone(),
                (
                    artifact.get_source_map()?.ok()?,
                    artifact
                        .get_deployed_bytecode()
                        .as_ref()?
                        .bytecode
                        .as_ref()?
                        .source_map()?
                        .ok()?,
                ),
            );
            let bytecodes = (
                contract_id,
                (
                    artifact
                        .get_bytecode()
                        .and_then(|bytecode| dummy_link_bytecode(bytecode.into_owned()))?,
                    artifact.get_deployed_bytecode().and_then(|bytecode| {
                        dummy_link_deployed_bytecode(bytecode.into_owned())
                    })?,
                ),
            );

            Some((source_maps, bytecodes))
        })
        .unzip();

    // Build IC -> PC mappings
    //
    // The source maps are indexed by *instruction counters*, which are the indexes of
    // instructions in the bytecode *minus any push bytes*.
    //
    // Since our coverage inspector collects hit data using program counters, the anchors also
    // need to be based on program counters.
    // TODO: Index by contract ID
    let ic_pc_maps: HashMap<ContractId, (IcPcMap, IcPcMap)> = bytecodes
        .iter()
        .map(|(id, bytecodes)| {
            // TODO: Creation bytecode as well
            (
                id.clone(),
                (
                    IcPcMap::new(SpecId::LATEST, bytecodes.0.as_ref()),
                    IcPcMap::new(SpecId::LATEST, bytecodes.1.as_ref()),
                ),
            )
        })
        .collect();
    debug!("Number of versioned_asts: {}", versioned_asts.len());
    // Add coverage items
    for (version, asts) in versioned_asts.into_iter() {
        let source_analysis = SourceAnalyzer::new(
            version.clone(),
            asts,
            versioned_sources.remove(&version).ok_or_else(|| {
                eyre::eyre!(
                    "File tree is missing source code, cannot perform coverage analysis"
                )
            })?,
        )?
        .analyze()?;

        // Build helper mapping used by `find_anchors`
        let mut items_by_source_id: HashMap<_, Vec<_>> =
            HashMap::with_capacity(source_analysis.items.len());

        for (item_id, item) in source_analysis.items.iter().enumerate() {
            items_by_source_id.entry(item.loc.source_id).or_default().push(item_id);
        }

        let anchors: HashMap<ContractId, Vec<ItemAnchor>> = source_maps
            .iter()
            .filter(|(contract_id, _)| contract_id.version == version)
            .filter_map(|(contract_id, (_, deployed_source_map))| {
                // TODO: Creation source map/bytecode as well
                Some((
                    contract_id.clone(),
                    find_anchors(
                        &bytecodes.get(contract_id)?.1,
                        deployed_source_map,
                        &ic_pc_maps.get(contract_id)?.1,
                        &source_analysis.items,
                        &items_by_source_id,
                    ),
                ))
            })
            .collect();
        report.add_items(version, source_analysis.items);
        report.add_anchors(anchors);
    }

    report.add_source_maps(source_maps);

    Ok(report)
}

fn dummy_link_deployed_bytecode(obj: CompactDeployedBytecode) -> Option<Bytes> {
    obj.bytecode.and_then(dummy_link_bytecode)
}

fn dummy_link_bytecode(mut obj: CompactBytecode) -> Option<Bytes> {
    let link_references = obj.link_references.clone();
    for (file, libraries) in link_references {
        for library in libraries.keys() {
            obj.link(&file, library, Address::ZERO);
        }
    }

    obj.object.resolve();
    obj.object.into_bytes()
}

#[tokio::main]
async fn main() -> Result<()> {
    handler::install();
    utils::load_dotenv();
    utils::subscriber();
    utils::enable_paint();

    let args = TxCoverage::parse();
    args.run().await?;
    Ok(())
}