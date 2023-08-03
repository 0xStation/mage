// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IInitializerInternal {
    // events
    event Initialized();

    // errors
    error AlreadyInitialized();
    error NotInitializing();

    // views
    function initialized() external view returns (bool);
}

interface IInitializer is IInitializerInternal {}
