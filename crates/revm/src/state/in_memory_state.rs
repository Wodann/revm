use crate::primitives::{
    hash_map::Entry, Account, AccountInfo, Bytecode, HashMap, B160, B256, KECCAK_EMPTY, U256,
};
use core::convert::Infallible;
use revm_interpreter::primitives::db::{DatabaseCommit, State, StateRef};

pub type InMemoryState = CacheState<EmptyState>;

impl Default for InMemoryState {
    fn default() -> Self {
        CacheState::new(EmptyState)
    }
}

/// Memory backend, storing all state values in a `Map` in memory.
#[derive(Debug, Clone)]
pub struct CacheState<Ext: StateRef> {
    /// Account info where None means it is not existing. Not existing state is needed for Pre TANGERINE forks.
    /// `code` is always `None`, and bytecode can be found in `contracts`.
    pub accounts: HashMap<B160, StateAccount>,
    pub contracts: HashMap<B256, Bytecode>,
    pub ext: Ext,
}

#[derive(Debug, Clone, Default)]
pub struct StateAccount {
    pub info: AccountInfo,
    /// If account is selfdestructed or newly created, storage will be cleared.
    pub account_state: AccountState,
    /// storage slots
    pub storage: HashMap<U256, U256>,
}

impl StateAccount {
    pub fn new_not_existing() -> Self {
        Self {
            account_state: AccountState::NotExisting,
            ..Default::default()
        }
    }
    pub fn info(&self) -> Option<AccountInfo> {
        if matches!(self.account_state, AccountState::NotExisting) {
            None
        } else {
            Some(self.info.clone())
        }
    }
}

impl From<Option<AccountInfo>> for StateAccount {
    fn from(from: Option<AccountInfo>) -> Self {
        if let Some(info) = from {
            Self {
                info,
                account_state: AccountState::None,
                ..Default::default()
            }
        } else {
            Self::new_not_existing()
        }
    }
}

impl From<AccountInfo> for StateAccount {
    fn from(info: AccountInfo) -> Self {
        Self {
            info,
            account_state: AccountState::None,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum AccountState {
    /// Before Spurious Dragon hardfork there were a difference between empty and not existing.
    /// And we are flaging it here.
    NotExisting,
    /// EVM touched this account. For newer hardfork this means it can be clearead/removed from state.
    Touched,
    /// EVM cleared storage of this account, mostly by selfdestruct, we dont ask database for storage slots
    /// and asume they are U256::ZERO
    StorageCleared,
    /// EVM didnt interacted with this account
    #[default]
    None,
}

impl<Ext: StateRef> CacheState<Ext> {
    pub fn new(db: Ext) -> Self {
        let mut contracts = HashMap::new();
        contracts.insert(KECCAK_EMPTY, Bytecode::new());
        contracts.insert(B256::zero(), Bytecode::new());
        Self {
            accounts: HashMap::new(),
            contracts,
            ext: db,
        }
    }

    pub fn insert_contract(&mut self, account: &mut AccountInfo) {
        if let Some(code) = &account.code {
            if !code.is_empty() {
                account.code_hash = code.hash();
                self.contracts
                    .entry(account.code_hash)
                    .or_insert_with(|| code.clone());
            }
        }
        if account.code_hash == B256::zero() {
            account.code_hash = KECCAK_EMPTY;
        }
    }

    /// Insert account info but not override storage
    pub fn insert_account_info(&mut self, address: B160, mut info: AccountInfo) {
        self.insert_contract(&mut info);
        self.accounts.entry(address).or_default().info = info;
    }

    pub fn load_account(&mut self, address: B160) -> Result<&mut StateAccount, Ext::Error> {
        let db = &self.ext;
        match self.accounts.entry(address) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(entry.insert(
                db.basic(address)?
                    .map(|info| StateAccount {
                        info,
                        ..Default::default()
                    })
                    .unwrap_or_else(StateAccount::new_not_existing),
            )),
        }
    }

    /// insert account storage without overriding account info
    pub fn insert_account_storage(
        &mut self,
        address: B160,
        slot: U256,
        value: U256,
    ) -> Result<(), Ext::Error> {
        let account = self.load_account(address)?;
        account.storage.insert(slot, value);
        Ok(())
    }

    /// replace account storage without overriding account info
    pub fn replace_account_storage(
        &mut self,
        address: B160,
        storage: HashMap<U256, U256>,
    ) -> Result<(), Ext::Error> {
        let account = self.load_account(address)?;
        account.account_state = AccountState::StorageCleared;
        account.storage = storage.into_iter().collect();
        Ok(())
    }
}

impl<Ext: StateRef> DatabaseCommit for CacheState<Ext> {
    fn commit(&mut self, changes: HashMap<B160, Account>) {
        for (address, mut account) in changes {
            if account.is_destroyed {
                let db_account = self.accounts.entry(address).or_default();
                db_account.storage.clear();
                db_account.account_state = AccountState::NotExisting;
                db_account.info = AccountInfo::default();
                continue;
            }
            self.insert_contract(&mut account.info);

            let db_account = self.accounts.entry(address).or_default();
            db_account.info = account.info;

            db_account.account_state = if account.storage_cleared {
                db_account.storage.clear();
                AccountState::StorageCleared
            } else {
                AccountState::Touched
            };
            db_account.storage.extend(
                account
                    .storage
                    .into_iter()
                    .map(|(key, value)| (key, value.present_value())),
            );
        }
    }
}

impl<Ext: StateRef> State for CacheState<Ext> {
    type Error = Ext::Error;

    fn basic(&mut self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        let basic = match self.accounts.entry(address) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                self.ext
                    .basic(address)?
                    .map(|info| StateAccount {
                        info,
                        ..Default::default()
                    })
                    .unwrap_or_else(StateAccount::new_not_existing),
            ),
        };
        Ok(basic.info())
    }

    /// Get the value in an account's storage slot.
    ///
    /// It is assumed that account is already loaded.
    fn storage(&mut self, address: B160, index: U256) -> Result<U256, Self::Error> {
        match self.accounts.entry(address) {
            Entry::Occupied(mut acc_entry) => {
                let acc_entry = acc_entry.get_mut();
                match acc_entry.storage.entry(index) {
                    Entry::Occupied(entry) => Ok(*entry.get()),
                    Entry::Vacant(entry) => {
                        if matches!(
                            acc_entry.account_state,
                            AccountState::StorageCleared | AccountState::NotExisting
                        ) {
                            Ok(U256::ZERO)
                        } else {
                            let slot = self.ext.storage(address, index)?;
                            entry.insert(slot);
                            Ok(slot)
                        }
                    }
                }
            }
            Entry::Vacant(acc_entry) => {
                // acc needs to be loaded for us to access slots.
                let info = self.ext.basic(address)?;
                let (account, value) = if info.is_some() {
                    let value = self.ext.storage(address, index)?;
                    let mut account: StateAccount = info.into();
                    account.storage.insert(index, value);
                    (account, value)
                } else {
                    (info.into(), U256::ZERO)
                };
                acc_entry.insert(account);
                Ok(value)
            }
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.contracts.entry(code_hash) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                // if you return code bytes when basic fn is called this function is not needed.
                Ok(entry.insert(self.ext.code_by_hash(code_hash)?).clone())
            }
        }
    }
}

impl<Ext: StateRef> StateRef for CacheState<Ext> {
    type Error = Ext::Error;

    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        match self.accounts.get(&address) {
            Some(acc) => Ok(acc.info()),
            None => self.ext.basic(address),
        }
    }

    fn storage(&self, address: B160, index: U256) -> Result<U256, Self::Error> {
        match self.accounts.get(&address) {
            Some(acc_entry) => match acc_entry.storage.get(&index) {
                Some(entry) => Ok(*entry),
                None => {
                    if matches!(
                        acc_entry.account_state,
                        AccountState::StorageCleared | AccountState::NotExisting
                    ) {
                        Ok(U256::ZERO)
                    } else {
                        self.ext.storage(address, index)
                    }
                }
            },
            None => self.ext.storage(address, index),
        }
    }

    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.contracts.get(&code_hash) {
            Some(entry) => Ok(entry.clone()),
            None => self.ext.code_by_hash(code_hash),
        }
    }
}

/// An empty database that always returns default values when queried.
#[derive(Debug, Default, Clone)]
pub struct EmptyState;

impl StateRef for EmptyState {
    type Error = Infallible;

    fn basic(&self, _address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(None)
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::new())
    }

    fn storage(&self, _address: B160, _index: U256) -> Result<U256, Self::Error> {
        Ok(U256::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheState, EmptyState, StateRef};
    use crate::primitives::{AccountInfo, U256};

    #[test]
    pub fn test_insert_account_storage() {
        let account = 42.into();
        let nonce = 42;
        let mut init_state = CacheState::new(EmptyState::default());
        init_state.insert_account_info(
            account,
            AccountInfo {
                nonce,
                ..Default::default()
            },
        );

        let (key, value) = (U256::from(123), U256::from(456));
        let mut new_state = CacheState::new(init_state);
        let _ = new_state.insert_account_storage(account, key, value);

        assert_eq!(new_state.basic(account).unwrap().unwrap().nonce, nonce);
        assert_eq!(new_state.storage(account, key), Ok(value));
    }

    #[test]
    pub fn test_replace_account_storage() {
        let account = 42.into();
        let nonce = 42;
        let mut init_state = CacheState::new(EmptyState::default());
        init_state.insert_account_info(
            account,
            AccountInfo {
                nonce,
                ..Default::default()
            },
        );

        let (key0, value0) = (U256::from(123), U256::from(456));
        let (key1, value1) = (U256::from(789), U256::from(999));
        let _ = init_state.insert_account_storage(account, key0, value0);

        let mut new_state = CacheState::new(init_state);
        let _ = new_state.replace_account_storage(account, [(key1, value1)].into());

        assert_eq!(new_state.basic(account).unwrap().unwrap().nonce, nonce);
        assert_eq!(new_state.storage(account, key0), Ok(U256::ZERO));
        assert_eq!(new_state.storage(account, key1), Ok(value1));
    }
}
