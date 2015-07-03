// Stochastic address manager

import std.socket: Address;


enum AddrGroup
{
    DEFAULT
}

class PeerAddress : Address
{
    /// Get identifier of an address's group
    /// No two connections will be attempted to addresses of the same group
    AddrGroup getAddrGroup() const
    {
        return AddrGroup.DEFAULT;
    }
}
