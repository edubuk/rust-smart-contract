/// Edubuk eSeal Smart Contract using Rust Language deployed on the Concordium Blockchain
#![cfg_attr(not(feature = "std"), no_std)]
use concordium_std::*;

/// The different errors the contract can produce.
#[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType)]
pub enum ContractError {
    /// Failed parsing the parameter.
    #[from(ParseError)]
    ParseParams,
    /// Failed logging: Log is full.
    LogFull,
    /// Failed logging: Log is malformed.
    LogMalformed,
    /// Only accounts can register a file hash.
    OnlyAccount,
    /// Each file hash can only be registered once.
    AlreadyRegistered,
    /// If file was not found in state.
    NotFound,
}

/// Mapping the logging errors to ContractError.
impl From<LogError> for ContractError {
    fn from(le: LogError) -> Self {
        match le {
            LogError::Full => Self::LogFull,
            LogError::Malformed => Self::LogMalformed,
        }
    }
}

/// The Name type to store names of the certified personnels.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Clone, Copy, SchemaType)]
pub struct Name(pub [u8; 50]);

/// The Authority type to store the name of the certifying authority.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Clone, Copy, SchemaType)]
pub struct Authority(pub [u8; 50]);

/// The Certificate Type of the certificate to be stored on the concordium blockchain.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Clone, Copy, SchemaType)]
pub struct CertType(pub [u8; 50]);

/// The state tracked for each file.
#[derive(Serialize, Clone, Copy, SchemaType, PartialEq, Eq, Debug)]
pub struct FileState {
    /// The name of the person certified.
    pub name: Name,
    /// Name of the certifying authority.
    pub authority: Authority,
    /// Certificate type.
    pub cert_type: CertType,
    /// The filehash of the certificate.
    pub filehash: HashSha2256,
    /// The timestamp when this file hash was registered.
    pub timestamp: Timestamp,
    /// The witness (sender_account) that registered this file hash.
    pub witness: AccountAddress,
}

/// The contract state.
#[derive(Serial, DeserialWithState)]
#[concordium(state_parameter = "S")]
struct State<S = StateApi> {
    files: StateMap<HashSha2256, FileState, S>,
}

impl State {
    /// Create a new state with no files registered.
    fn new(state_builder: &mut StateBuilder) -> Self {
        State {
            files: state_builder.new_map(),
        }
    }

    /// Check if a file exists.
    fn file_exists(&self, file_hash: &HashSha2256) -> bool {
        let file = self.files.get(file_hash);

        file.is_some()
    }

    /// Get recorded FileState:
    /// - name, authority, cert_type, filehash, timestamp and witness
    /// from a specific file hash.
    fn get_file_state(&self, file_hash: HashSha2256) -> Option<FileState> {
        self.files.get(&file_hash).map(|v| *v)
    }

    /// Add a new file hash (replaces existing file if present).
    fn add_file(
        &mut self,
        file_hash: HashSha2256,
        name: Name,
        authority: Authority,
        cert_type: CertType,
        timestamp: Timestamp,
        witness: AccountAddress,
    ) {
        self.files.insert(
            file_hash,
            FileState {
                name,
                authority,
                cert_type,
                filehash: file_hash,
                timestamp,
                witness,
            },
        );
    }
}

/// Tagged events to be serialized for the event log.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub enum Event {
    Registration(RegistrationEvent),
}

/// The RegistrationEvent is logged when a new file hash is registered.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct RegistrationEvent {
    /// Name of the certified person.
    pub name: Name,
    /// Name of the certifying authority.
    pub authority: Authority,
    /// Type of certificate.
    pub cert_type: CertType,
    /// Hash of the file to be registered by the witness (sender_account).
    pub file_hash: HashSha2256,
    /// Witness (sender_account) that registered the above file hash.
    pub witness: AccountAddress,
    /// Timestamp when this file hash was registered in the smart contract.
    pub timestamp: Timestamp,
}

/// Init function that creates this eSealing smart contract.
#[init(contract = "eSealing", event = "Event")]
fn contract_init(_ctx: &InitContext, state_builder: &mut StateBuilder) -> InitResult<State> {
    Ok(State::new(state_builder))
}

#[derive(Debug, Serialize, SchemaType, Clone, PartialEq, Eq)]
pub struct RecFile {
    pub name: String,
    pub authority: String,
    pub cert_type: String,
    pub filehash: HashSha2256,
}

/// Register a new file.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - If the file hash has already been registered.
/// - If a smart contract tries to register the file hash.
#[receive(
    contract = "eSealing",
    name = "registerFile",
    parameter = "RecFile",
    error = "ContractError",
    mutable,
    enable_logger
)]
fn register_file(
    ctx: &ReceiveContext,
    host: &mut Host<State>,
    logger: &mut impl HasLogger,
) -> Result<(), ContractError> {
    // Ensure that only accounts can register a file.
    let sender_account = match ctx.sender() {
        Address::Contract(_) => bail!(ContractError::OnlyAccount),
        Address::Account(account_address) => account_address,
    };

    // Take the request parameters from receive context.
    let rec_file: RecFile = ctx.parameter_cursor().get()?;
    let xname: String = rec_file.name;
    let mut name: Name = Name([0u8; 50]);
    for (i, v) in xname.as_bytes().iter().enumerate() {
        name.0[i] = *v;
    }
    let xauthority: String = rec_file.authority;
    let mut authority: Authority = Authority([0u8; 50]);
    for (i, v) in xauthority.as_bytes().iter().enumerate() {
        authority.0[i] = *v;
    }
    let xcert_type: String = rec_file.cert_type;
    let mut cert_type: CertType = CertType([0u8; 50]);
    for (i, v) in xcert_type.as_bytes().iter().enumerate() {
        cert_type.0[i] = *v;
    }
    let file_hash: HashSha2256 = rec_file.filehash;

    if host.state().file_exists(&file_hash) {
        return Err(ContractError::AlreadyRegistered);
    } else {
        // Take the timestamp from the ReceiveContext
        let timestamp = ctx.metadata().slot_time();

        // Register the file hash.
        host.state_mut().add_file(
            file_hash,
            name,
            authority,
            cert_type,
            timestamp,
            sender_account,
        );

        // Log the event.
        logger.log(&Event::Registration(RegistrationEvent {
            name,
            authority,
            cert_type,
            file_hash,
            witness: sender_account,
            timestamp,
        }))?;

        Ok(())
    }
}

/// Get the `FileState` (timestamp and witness) of a registered file hash.
/// If the file hash has not been registered, this query returns `None`.
///
/// It rejects if:
/// - It fails to parse the parameter.
#[receive(
    contract = "eSealing",
    name = "getFile",
    parameter = "HashSha2256",
    error = "ContractError",
    return_value = "Option<FileState>"
)]
fn get_file(ctx: &ReceiveContext, host: &Host<State>) -> ReceiveResult<Option<FileState>> {
    let file_hash: HashSha2256 = ctx.parameter_cursor().get()?;

    Ok(host.state().get_file_state(file_hash))
}
