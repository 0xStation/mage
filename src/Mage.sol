// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UUPSUpgradeable} from "openzeppelin-contracts/proxy/utils/UUPSUpgradeable.sol";
import {Multicall} from "openzeppelin-contracts/utils/Multicall.sol";

import {Access} from "./access/Access.sol";
import {Guards} from "./guard/Guards.sol";
import {Extensions} from "./extension/Extensions.sol";
import {SupportsInterface} from "./lib/ERC165/SupportsInterface.sol";
import {Execute} from "./lib/Execute.sol";
import {Operations} from "./lib/Operations.sol";

/**
 * A Solidity framework for creating complex and evolving onchain structures.
 * Mage is an acronym for the architecture pattern's four layers: Module, Access, Guard, and Extension.
 * All Mage-inherited contracts receive a batteries-included contract development kit.
 */
abstract contract Mage is Access, Guards, Extensions, SupportsInterface, Execute, Multicall, UUPSUpgradeable {
    function contractURI() public view virtual returns (string memory uri) {}

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(Access, Guards, Extensions, SupportsInterface)
        returns (bool)
    {
        return Access.supportsInterface(interfaceId) || Guards.supportsInterface(interfaceId)
            || Extensions.supportsInterface(interfaceId) || SupportsInterface.supportsInterface(interfaceId);
    }

    function _beforeExecute(address to, uint256 value, bytes calldata data) internal view override returns (address guard, bytes memory checkBeforeData) {
        return checkGuardBefore(Operations.CALL, abi.encode(to, value, data));
    }

    function _afterExecute(address guard, bytes memory checkBeforeData, bytes memory executeData) internal view override {
        checkGuardAfter(guard, checkBeforeData, executeData);
    }
}
