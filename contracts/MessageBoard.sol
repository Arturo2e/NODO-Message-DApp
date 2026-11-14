// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MessageBoard
/// @notice Registra hashes (no texto) y pagos opcionales para mensajes EVM.
contract MessageBoard {
    enum Status { Sent, Read, Cancelled }

    struct Message {
        address sender;
        address recipient;
        bytes32 contentHash;
        uint64 createdAt;
        uint256 amount;
        Status status;
    }

    address public immutable owner;
    mapping(address => bool) public moderators;
    mapping(uint256 => bool) public paymentClaimed;
    mapping(uint256 => bool) public flagged;

    Message[] private messages;
    mapping(address => uint256[]) private inboxIds;
    mapping(address => uint256[]) private sentIds;

    event MessageSent(uint256 indexed id, address indexed sender, address indexed recipient, bytes32 contentHash, uint256 amount);
    event MessageRead(uint256 indexed id, address indexed recipient);
    event MessageCancelled(uint256 indexed id, address indexed sender);
    event MessageFlagged(uint256 indexed id, address indexed moderator);
    event ModeratorUpdated(address indexed account, bool enabled);
    event PaymentWithdrawn(uint256 indexed id, address indexed account, uint256 amount);

    error InvalidAddress();
    error InvalidHash();
    error InvalidMessage();
    error AlreadyFinalized();
    error PaymentAlreadyClaimed();
    error TransferFailed();

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyModerator() {
        require(msg.sender == owner || moderators[msg.sender], "Not moderator");
        _;
    }

    constructor() {
        owner = msg.sender;
        moderators[msg.sender] = true;
        emit ModeratorUpdated(msg.sender, true);
    }

    /// @dev The content stays off-chain; callers submit a Keccak-256 hash.
    function sendMessage(address recipient, bytes32 contentHash) external payable returns (uint256 id) {
        if (recipient == address(0)) revert InvalidAddress();
        if (recipient == msg.sender) revert InvalidMessage();
        if (contentHash == bytes32(0)) revert InvalidHash();
        if (block.timestamp > type(uint64).max) revert InvalidMessage();

        id = messages.length;
        messages.push(Message({
            sender: msg.sender,
            recipient: recipient,
            contentHash: contentHash,
            // forge-lint: disable-next-line(unsafe-typecast)
            createdAt: uint64(block.timestamp),
            amount: msg.value,
            status: Status.Sent
        }));
        inboxIds[recipient].push(id);
        sentIds[msg.sender].push(id);
        emit MessageSent(id, msg.sender, recipient, contentHash, msg.value);
    }

    function getInboxIds(address account) external view returns (uint256[] memory) {
        return inboxIds[account];
    }

    function getSentIds(address account) external view returns (uint256[] memory) {
        return sentIds[account];
    }

    function getMessage(uint256 id) external view returns (
        address sender,
        address recipient,
        bytes32 contentHash,
        uint64 createdAt,
        uint256 amount,
        bool isRead,
        bool cancelled
    ) {
        if (id >= messages.length) revert InvalidMessage();
        Message storage item = messages[id];
        return (
            item.sender,
            item.recipient,
            item.contentHash,
            item.createdAt,
            item.amount,
            item.status == Status.Read,
            item.status == Status.Cancelled
        );
    }

    function messageCount() external view returns (uint256) {
        return messages.length;
    }

    /// @notice Only the addressed recipient can mark a record as read.
    function markRead(uint256 id) external {
        require(id < messages.length && messages[id].recipient == msg.sender, "Not recipient");
        if (messages[id].status != Status.Sent) revert AlreadyFinalized();
        messages[id].status = Status.Read;
        emit MessageRead(id, msg.sender);
    }

    /// @notice Sender can cancel an unread message; an unclaimed payment is refunded.
    function cancelMessage(uint256 id) external {
        require(id < messages.length && messages[id].sender == msg.sender, "Not sender");
        Message storage item = messages[id];
        if (item.status != Status.Sent) revert AlreadyFinalized();
        item.status = Status.Cancelled;
        emit MessageCancelled(id, msg.sender);
        if (item.amount > 0) {
            if (paymentClaimed[id]) revert PaymentAlreadyClaimed();
            paymentClaimed[id] = true;
            (bool success,) = payable(item.sender).call{value: item.amount}("");
            if (!success) revert TransferFailed();
        }
    }

    /// @notice A moderator flags a record without deleting or altering its public evidence.
    function flagMessage(uint256 id) external onlyModerator {
        if (id >= messages.length) revert InvalidMessage();
        flagged[id] = true;
        emit MessageFlagged(id, msg.sender);
    }

    function setModerator(address account, bool enabled) external onlyOwner {
        if (account == address(0)) revert InvalidAddress();
        moderators[account] = enabled;
        emit ModeratorUpdated(account, enabled);
    }

    /// @notice Recipient claims the payment attached to one message, once.
    function withdraw(uint256 id) external {
        require(id < messages.length && messages[id].recipient == msg.sender, "Not recipient");
        Message storage item = messages[id];
        if (item.amount == 0 || paymentClaimed[id]) revert PaymentAlreadyClaimed();
        paymentClaimed[id] = true;
        emit PaymentWithdrawn(id, msg.sender, item.amount);
        (bool success,) = payable(msg.sender).call{value: item.amount}("");
        if (!success) revert TransferFailed();
    }
}
