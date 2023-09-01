// SPDX-License-Identifier: CC-PDDC

pragma solidity ^0.8.0;

import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

contract E2EProxy {
    Sapphire.Curve25519PublicKey internal immutable publicKey;

    Sapphire.Curve25519SecretKey internal immutable privateKey;

    constructor (bytes memory extra_entropy) {
        (publicKey, privateKey) = Sapphire.generateCurve25519KeyPair(extra_entropy);
    }

    function getPublicKey()
        external view
        returns (bytes32)
    {
        return Sapphire.Curve25519PublicKey.unwrap(publicKey);
    }

    function personalization(uint256 value)
        public pure
        returns (bytes memory)
    {
        return "";
        /*
        return abi.encodePacked(
            block.chainid,
            address(this),
            msg.sender,
            value
        );
        */
    }

    function encryptCall (bytes32 symmetricKey, address addr, bytes memory subcall_data, uint256 value)
        public view
        returns (bytes32 nonce, bytes memory ciphertext)
    {
        nonce = bytes32(Sapphire.randomBytes(32, ""));

        bytes memory plaintext = abi.encode(addr, subcall_data);

        ciphertext = Sapphire.encrypt(symmetricKey, nonce, plaintext, personalization(value));
    }

    function proxy(bytes32 peerPublicKey, bytes32 nonce, bytes memory data)
        external payable
        returns (bytes memory)
    {
        bytes32 symmetricKey = Sapphire.deriveSymmetricKey(Sapphire.Curve25519PublicKey.wrap(peerPublicKey), privateKey);

        bytes memory plaintext = Sapphire.decrypt(symmetricKey, nonce, data, personalization(msg.value));

        (address addr, bytes memory subcall_data) = abi.decode(plaintext, (address, bytes));

        require( addr != address(this), "Cannot call this!" );

        (bool success, bytes memory out_data) = addr.call{value: msg.value}(subcall_data);
        assembly {
            switch success
            case 0 { revert(add(out_data,32),mload(out_data)) }
        }

        return out_data;
    }
}
