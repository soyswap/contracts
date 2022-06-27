// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SoyswapToken is ERC20, ERC20Permit, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant RESCUER_ROLE = keccak256("RESCUER_ROLE");
    bytes32 public constant TAKE_FEE_ROLE = keccak256("TAKE_FEE_ROLE");
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    uint256 private _maxSupply = 1000000 * 10**decimals(); // 1M tokens is maximum supply

    event TokensRescued(address indexed sender, address indexed token, uint256 value);

    constructor() ERC20("Soyswap Token", "SOY") ERC20Permit("Soyswap Token") {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function _msgSender() internal view override returns (address) {
        return msg.sender;
    }

    /**
     * @dev Returns the maximum amount of tokens that can be minted.
     */
    function maxSupply() public view returns (uint256) {
        return _maxSupply;
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= _maxSupply, "ERC20: cannot mint more tokens, cap exceeded");
        _mint(to, amount);
    }

    function rescueTokens(IERC20 token, uint256 value) external onlyRole(RESCUER_ROLE) {
        token.transfer(_msgSender(), value);

        emit TokensRescued(_msgSender(), address(token), value);
    }

}
