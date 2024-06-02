// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IRoles} from "./interface/IRoles.sol";
import {RolesStorage as Storage} from "./RolesStorage.sol";

abstract contract Roles is IRoles {
    /*===========
        VIEWS
    ===========*/

    /// @inheritdoc IRoles
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        (bytes32 grantedRoleKey, bytes20 roleSuffix) = Storage._packKey(account, role);
        Storage.GrantedRoleData memory grantedRole = Storage.layout()._grantedRoles[grantedRoleKey];
        return grantedRole.exists && grantedRole.roleSuffix == roleSuffix;
    }

    /// @inheritdoc IRoles
    function getAllGrantedRoles() public view returns (GrantedRole[] memory grantedRoles) {
        Storage.Layout storage layout = Storage.layout();
        uint256 len = layout._grantedRoleKeys.length;
        grantedRoles = new GrantedRole[](len);
        for (uint256 i; i < len; i++) {
            bytes32 grantedRoleKey = layout._grantedRoleKeys[i];
            (address account, bytes12 rolePrefix) = Storage._unpackKey(grantedRoleKey);
            Storage.GrantedRoleData memory grantedRole = layout._grantedRoles[grantedRoleKey];
            grantedRoles[i] =
                GrantedRole(Storage._stitchRole(rolePrefix, grantedRole.roleSuffix), account, uint40(block.timestamp));
        }
        return grantedRoles;
    }

    /// @inheritdoc IRoles
    function checkRole(bytes32 role, address account) public view {
        _checkRole(role, account);
    }

    /// @dev Function to implement ERC-165 compliance
    /// @param interfaceId The interface identifier to check.
    /// @return _ Boolean indicating whether the contract supports the specified interface.
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IRoles).interfaceId;
    }

    /*=============
        SETTERS
    =============*/

    /// @inheritdoc IRoles
    function grantRole(bytes32 role, address account) public virtual {
        _checkCanUpdateRoles();
        _grantRole(role, account);
    }

    /// @inheritdoc IRoles
    function revokeRole(bytes32 role, address account) public virtual {
        _checkCanUpdateRoles();
        _revokeRole(role, account);
    }

    /// @inheritdoc IRoles
    function renounceRole(bytes32 role, address account) public virtual {
        require(msg.sender == account);
        _revokeRole(role, account);
    }

    /*===============
        INTERNALS
    ===============*/

    function _grantRole(bytes32 role, address account) internal {
        Storage.Layout storage layout = Storage.layout();
        (bytes32 grantedRoleKey, bytes20 roleSuffix) = Storage._packKey(account, role);
        if (layout._grantedRoles[grantedRoleKey].exists) {
            if (layout._grantedRoles[grantedRoleKey].roleSuffix == roleSuffix) {
                bytes12 rolePrefix = bytes12(role);
                revert RolePrefixCollision(
                    role, bytes32(uint256(uint96(rolePrefix)) << 160 | uint256(uint160(roleSuffix)))
                );
            } else {
                revert RoleAlreadyGranted(role, account);
            }
        }
        // new length will be `len + 1`, so this grantedRole has index `len`
        Storage.GrantedRoleData memory grantedRole =
            Storage.GrantedRoleData(uint24(layout._grantedRoleKeys.length), uint40(block.timestamp), true, roleSuffix);

        layout._grantedRoles[grantedRoleKey] = grantedRole;
        layout._grantedRoleKeys.push(grantedRoleKey); // set new grantedRoleKey at index and increment length

        emit RoleGranted(role, account, msg.sender);
    }

    function _revokeRole(bytes32 role, address account) internal {
        Storage.Layout storage layout = Storage.layout();
        (bytes32 grantedRoleKey, bytes20 roleSuffix) = Storage._packKey(account, role);
        Storage.GrantedRoleData memory oldGrantedRoleData = layout._grantedRoles[grantedRoleKey];
        if (!(oldGrantedRoleData.exists && oldGrantedRoleData.roleSuffix == roleSuffix)) {
            revert RoleNotGranted(role, account);
        }

        uint256 lastIndex = layout._grantedRoleKeys.length - 1;
        // if removing item not at the end of the array, swap item with last in array
        if (oldGrantedRoleData.index < lastIndex) {
            bytes32 lastRoleKey = layout._grantedRoleKeys[lastIndex];
            Storage.GrantedRoleData memory lastGrantedRoleData = layout._grantedRoles[lastRoleKey];
            lastGrantedRoleData.index = oldGrantedRoleData.index;
            layout._grantedRoleKeys[oldGrantedRoleData.index] = lastRoleKey;
            layout._grantedRoles[lastRoleKey] = lastGrantedRoleData;
        }
        delete layout._grantedRoles[grantedRoleKey];
        layout._grantedRoleKeys.pop(); // delete guard in last index and decrement length

        emit RoleRevoked(role, account, msg.sender);
    }

    /*===================
        AUTHORIZATION
    ===================*/

    modifier onlyRole(bytes32 role) {
        _checkRole(role, msg.sender);
        _;
    }

    /// @dev Function to ensure `account` has grantedRole to carry out `role`
    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) revert RoleNotGranted(role, account);
    }

    /// @dev Function to implement access control restricting setter functions
    function _checkCanUpdateRoles() internal virtual;
}
