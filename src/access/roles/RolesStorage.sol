// SPDX-License-Identifier: MIT

pragma solidity ^0.8.8;

library RolesStorage {
    bytes32 internal constant SLOT = keccak256(abi.encode(uint256(keccak256("0xrails.Roles")) - 1));

    struct Layout {
        bytes32[] _grantedRoleKeys;
        mapping(bytes32 => GrantedRoleData) _grantedRoles;
    }

    struct GrantedRoleData {
        uint24 index; //       [0..23]
        uint40 updatedAt; //   [24..63]
        bool exists; //        [64-71]
        bytes20 roleSuffix; // [72..232]
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }

    // key = 0x{address}{rolePrefix} where rolePrefix is the first 12 bytes of bytes32 role
    function _packKey(address account, bytes32 role) internal pure returns (bytes32 key, bytes20 roleSuffix) {
        key = bytes32(uint256(uint160(account)) << 96 | (uint96(bytes12(role))));
        return (key, bytes20(uint160(uint256(role))));
    }

    function _unpackKey(bytes32 key) internal pure returns (address account, bytes12 rolePrefix) {
        account = address(bytes20(key));
        rolePrefix = bytes12(uint96(uint256(key)));
        return (account, rolePrefix);
    }

    function _stitchRole(bytes12 rolePrefix, bytes20 roleSuffix) internal pure returns (bytes32 role) {
        return bytes32(uint256(bytes32(rolePrefix)) | uint256(uint160(roleSuffix)));
    }
}
