// SPDX-License-Identifier: CC-PDDC

pragma solidity ^0.8.0;

interface SomeInterface {
    function transfer(address to, uint value) external;
}

contract Example {
    event Called(address from, uint value, bytes data);

    function transferFrom(address from, address to, uint amount)
        external
        payable
    {
        emit Called(msg.sender, msg.value, abi.encodeWithSelector(msg.sig, from, to, amount));
    }
}