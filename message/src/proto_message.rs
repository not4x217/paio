// This file is @generated by prost-build.
#[derive(Clone, PartialEq, ::prost::Message, serde::Serialize, serde::Deserialize)]
pub struct Batch {
    #[prost(bytes = "vec", tag = "1")]
    pub sequencer_payment_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub transactions: ::prost::alloc::vec::Vec<Transaction>,
}
#[derive(Clone, PartialEq, ::prost::Message, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    #[prost(bytes = "vec", tag = "1")]
    pub app: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub max_gas_price: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signature: ::core::option::Option<Signature>,
}
#[derive(Clone, PartialEq, ::prost::Message, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    #[prost(message, optional, tag = "1")]
    pub v: ::core::option::Option<Parity>,
    #[prost(bytes = "vec", tag = "2")]
    pub r: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub s: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, PartialEq, ::prost::Message, serde::Serialize, serde::Deserialize)]
pub struct Parity {
    #[prost(enumeration = "parity::Type", tag = "1")]
    pub r#type: i32,
    #[prost(uint64, tag = "2")]
    pub eip155_value: u64,
    #[prost(bool, tag = "3")]
    pub non_eip155_value: bool,
    #[prost(bool, tag = "4")]
    pub parity_value: bool,
}
/// Nested message and enum types in `Parity`.
pub mod parity {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
        serde::Serialize, 
        serde::Deserialize
    )]
    #[repr(i32)]
    pub enum Type {
        Eip155 = 0,
        NonEip155 = 1,
        Parity = 2,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Self::Eip155 => "EIP155",
                Self::NonEip155 => "NON_EIP155",
                Self::Parity => "PARITY",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "EIP155" => Some(Self::Eip155),
                "NON_EIP155" => Some(Self::NonEip155),
                "PARITY" => Some(Self::Parity),
                _ => None,
            }
        }
    }
}
