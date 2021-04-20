
use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer,
	}
};
use frame_support::traits::{Currency};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain::{http, Duration},
	AccountId32,
};

use sp_std::vec::Vec;
use lite_json::json::JsonValue;
#[cfg(test)]
mod tests;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"mypt");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
	};
	use sp_core::sr25519::Signature as Sr25519Signature;
	use frame_support::sp_runtime::{MultiSigner, MultiSignature};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

pub use pallet::*;
use sp_runtime::app_crypto::sp_core::crypto::UncheckedFrom;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use super::*;
	use sp_runtime::app_crypto::sp_core::crypto::UncheckedFrom;
	use frame_support::traits::Currency;
	// use frame_support::dispatch::DispatchErrorWithPostInfo;
	// use frame_support::weights::PostDispatchInfo;


	//type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
	/// This pallet's configuration trait
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_contracts::Config + CreateSignedTransaction<Call<Self>> where
		<Self as frame_system::Config>::AccountId: AsRef<[u8]>,
		<Self as frame_system::Config>::AccountId:UncheckedFrom<Self::Hash>,
		<<Self as pallet_contracts::Config>::Currency as Currency<<Self as frame_system::Config>::AccountId>>::Balance: From<u128>,
	{
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		type Currency: Currency<Self::AccountId>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
		where
			T::AccountId: UncheckedFrom<T::Hash>,
			T::AccountId: AsRef<[u8]>,
			<<T as pallet_contracts::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance: From<u128>,
	{
		fn offchain_worker(block_number: T::BlockNumber) {

			let parent_hash = <system::Pallet<T>>::block_hash(block_number - 1u32.into());
			log::info!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

			let transaction_type = block_number % 5u32.into();
			if transaction_type == T::BlockNumber::from(1u32) {
				let res = Self::call_contract();
				if let Err(e) = res {
					log::error!("Error: {}", e);
				} else {
					if let Err(e) = res {
						log::error!("Error: {}", e);
					}
				}
			}
		}
	}

	/// A public part of the pallet.
	#[pallet::call]
	impl<T: Config> Pallet<T> where
		T::AccountId:AsRef<[u8]>,
		T::AccountId:UncheckedFrom<T::Hash>,
		<<T as pallet_contracts::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance: From<u128>
	{
		#[pallet::weight(0)]
		pub fn set_update(origin: OriginFor<T>, address:T::AccountId, selector:Vec<u8>) -> DispatchResultWithPostInfo {
			let _who = ensure_signed(origin)?;
			<ContractAddress<T>>::put(address);
			<Selector<T>>::put(selector);
			Ok(().into())
		}

		#[pallet::weight(10_000)]
        fn call_contract_update(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;

            //合约地址
            //方法一：公钥形式
//            let contract_addr: AccountId = hex_literal::hex!["ca90852480d90c9bb0b1d53753f9a32e51ad2ca52137a464a56840127753e9f0"].to_vec().into();
//			let contract_addr: AccountId = AccountId::decode(&mut &bytes[..]).unwrap_or_default();
            //方法二：CREATE形式
//            let contract_addr = Contracts::contract_address(&ALICE, &caller_hash, &[]);
            //方法三：存储形式
            let contract_addr = <ContractAddress<T>>::get();

            //存储形式 input data
            let selector = <Selector<T>>::get();
            log::info!("address:{:?}, selector:{:?}", contract_addr, selector);
            let input_data = [&selector[..]].concat();
			// 方法二
//			let mut s = String::from("ecpandElc");
//			let selector = s.to_bytes().to_vec();
//			let input_data = [&selector[..]].concat();

			let exec_result = <pallet_contracts::Module<T>>::bare_call(_who, contract_addr, 0.into(), 600000000000000, input_data);
            match exec_result.exec_result {
                Ok(v) => {
                    let result_val = bool::decode(&mut &v.data[..]);
                    match result_val {
                        Ok(b) => {
                            log::info!("========{:?}",b);
                        },
                        Err(e) => { log::error!("{:?}",e)},
                    }
                },
                Err(e) => {
                    log::error!("==========={:?}",e);
                },
            }
            Ok(().into())
        }
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> where
		T::AccountId: UncheckedFrom<T::Hash>,
		T::AccountId: AsRef<[u8]>,
		<<T as pallet_contracts::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance: From<u128>
	{
		UpdatePrice((u128,u128), T::AccountId),
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> where
		T::AccountId: UncheckedFrom<T::Hash>,
		T::AccountId: AsRef<[u8]>,
		<<T as pallet_contracts::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance: From<u128>
	{
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		/// By default unsigned transactions are disallowed, but implementing the validator
		/// here we make sure that some particular calls (the ones produced by offchain worker)
		/// are being whitelisted and marked as valid.
		fn validate_unsigned(
			_source: TransactionSource,
			_call: &Self::Call,
		) -> TransactionValidity {
				InvalidTransaction::Call.into()
		 }
	}

	#[pallet::storage]
	#[pallet::getter(fn contract_address)]
	pub(super) type ContractAddress<T: Config> = StorageValue<_, T::AccountId, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn selector)]
    pub(super) type Selector<T: Config> = StorageValue<_, Vec<u8>, ValueQuery>;

}

impl<T: Config> Pallet<T>
	where
	T::AccountId: UncheckedFrom<T::Hash> ,
	T::AccountId: AsRef<[u8]>,
	<<T as pallet_contracts::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance: From<u128>
{

	pub fn call_contract()  -> Result<(), &'static str>  {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC."
			)?
		}
		// Using `send_signed_transaction` associated type we create and submit a transaction
		// representing the call, we've just created.
		// Submit signed will return a vector of results for all accounts that were found in the
		// local keystore with expected `KEY_TYPE`.
		let results = signer.send_signed_transaction(
			|_account| {
				// Received price is wrapped into a call to `submit_price` public function of this pallet.
				// This means that the transaction, when executed, will simply call that function passing
				// `price` as an argument.
				Call::call_contract_update()
			}
		);

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] update price ok!", acc.id),
				Err(e) => log::error!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		Ok(())
	}
}
