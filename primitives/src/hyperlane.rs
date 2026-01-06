use alloy_primitives::{Address, address};
use alloy_sol_types::sol;

pub const ETHEREUM_MERKLE_HOOK_CONTRACT: Address =
    address!("0x48e6c30B97748d1e2e03bf3e9FbE3890ca5f8CCA");
pub const SEPOLIA_MERKLE_HOOK_CONTRACT: Address =
    address!("0x4917a9746A7B6E0A57159cCb7F5a6744247f2d0d");

sol! {
    struct Output {
        bytes32 root;
        bytes32 stateRoot;
        uint64 blockNumber;
    }
    
    function root() public view returns (bytes32) {
        return _tree.root();
    }
}
